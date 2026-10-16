// Command wgmd is the privileged WGM daemon. It runs as root under systemd,
// monitors WireGuard tunnels, performs bounded recovery for tunnels it is
// authorized to manage, enforces the optional nftables kill switch and
// serves the local control socket used by wgm-ui.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/internal/auth"
	"github.com/cmerk2021/wgm/internal/backend"
	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/events"
	"github.com/cmerk2021/wgm/internal/firewall"
	"github.com/cmerk2021/wgm/internal/health"
	"github.com/cmerk2021/wgm/internal/ipc"
	"github.com/cmerk2021/wgm/internal/service"
	"github.com/cmerk2021/wgm/internal/sysexec"
	"github.com/cmerk2021/wgm/internal/tunnel"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

const (
	defaultPolicy   = "/etc/wgm/policy.json"
	defaultStateDir = "/var/lib/wgm"
	bootFileName    = "killswitch.nft"
)

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: wgmd [flags]                 run the daemon
       wgmd killswitch-restore [flags]   apply the saved kill switch (early boot)
       wgmd killswitch-disable [flags]   emergency: remove the kill switch and disable it
       wgmd check-policy [flags]         validate the policy file
       wgmd version

Flags:
`)
	flag.PrintDefaults()
}

func main() {
	var (
		configDir  = flag.String("config-dir", tunnel.DefaultConfigDir, "WireGuard configuration directory (read-only)")
		policyPath = flag.String("policy", defaultPolicy, "WGM policy file")
		stateDir   = flag.String("state-dir", defaultStateDir, "mutable state directory")
		socketPath = flag.String("socket", api.DefaultSocketPath, "control socket path")
		group      = flag.String("group", "wgm", "operator group allowed to use the control socket")
		adminGroup = flag.String("admin-group", "wheel", "group allowed to change ownership and kill switch settings")
		logLevel   = flag.String("log-level", "info", "debug, info, warn or error")
		noHistory  = flag.Bool("no-history", false, "disable SQLite event/metric history")
		devMode    = flag.Bool("unprivileged-dev", false, "development only: run without root (monitoring only; no tunnel control or kill switch)")
	)
	flag.Usage = usage
	cmd := ""
	args := os.Args[1:]
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	if err := flag.CommandLine.Parse(args); err != nil {
		os.Exit(2)
	}

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*logLevel)); err != nil {
		lvl = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)
	bootFile := filepath.Join(*stateDir, bootFileName)
	runner := sysexec.System{}

	switch cmd {
	case "version":
		fmt.Println("wgmd", version, "protocol", api.ProtocolVersion)
		return
	case "check-policy":
		data, err := os.ReadFile(*policyPath)
		if err != nil {
			fatal(err)
		}
		f, migrated, err := config.Migrate(data)
		if err == nil {
			err = f.Validate()
		}
		if err != nil {
			fatal(err)
		}
		fmt.Printf("policy OK (schema %d, revision %d, migration needed: %v)\n", f.SchemaVersion, f.Revision, migrated)
		return
	case "killswitch-restore":
		requireRoot()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := firewall.RestoreBootFile(ctx, firewall.NftCLI{Runner: runner}, bootFile); err != nil {
			fatal(fmt.Errorf("kill switch restore failed: %w", err))
		}
		return
	case "killswitch-disable":
		requireRoot()
		emergencyDisable(*policyPath, bootFile, runner)
		return
	case "":
	default:
		usage()
		os.Exit(2)
	}

	if os.Geteuid() != 0 && !*devMode {
		fatal(errors.New("wgmd must run as root (use the systemd unit); see --unprivileged-dev for development"))
	}
	if err := run(log, runner, *configDir, *policyPath, *stateDir, *socketPath, *group, *adminGroup, *noHistory, *devMode, bootFile); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wgmd:", err)
	os.Exit(1)
}

func requireRoot() {
	if os.Geteuid() != 0 {
		fatal(errors.New("this command must run as root"))
	}
}

func emergencyDisable(policyPath, bootFile string, runner sysexec.Runner) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := config.OpenStore(policyPath)
	if err == nil {
		if _, err := store.Update(0, func(f *config.File) error { f.KillSwitch.Enabled = false; return nil }); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not update policy:", err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "warning: policy unreadable, not updated:", err)
	}
	m := firewall.NewManager(firewall.NftCLI{Runner: runner}, bootFile)
	if err := m.Disable(ctx); err != nil {
		fatal(err)
	}
	fmt.Println("kill switch removed and disabled; restart wgmd if it is running")
}

func run(log *slog.Logger, runner sysexec.System, configDir, policyPath, stateDir, socketPath, group, adminGroup string, noHistory, dev bool, bootFile string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	store, err := config.OpenStore(policyPath)
	if err != nil {
		log.Error("policy file unusable; running with defaults and refusing to overwrite it", "path", policyPath, "err", err)
	}

	var hist *events.History
	if !noHistory {
		hist, err = events.OpenHistory(filepath.Join(stateDir, "history.db"))
		if err != nil {
			log.Error("history database unavailable; continuing without persistence", "err", err)
			hist = nil
		} else {
			defer hist.Close()
		}
	}

	reader := &tunnel.LinuxReader{Runner: runner}
	defer reader.Close()

	opts := service.Options{
		ConfigDir: configDir, Store: store, StatePath: filepath.Join(stateDir, "state.json"),
		Reader: reader, Prober: health.InterfaceProber{}, History: hist, Clock: health.SystemClock{}, Log: log,
		Resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		Version: version, OperatorGroup: group, AdminGroup: adminGroup,
	}
	if dev {
		opts.FirewallUnavailable = "daemon is running unprivileged (development mode)"
	} else {
		opts.Firewall = firewall.NewManager(firewall.NftCLI{Runner: runner}, bootFile)
		if runner.Available("wg-quick") {
			opts.Backend = &backend.WGQuick{Runner: runner, ConfigDir: configDir}
		} else {
			log.Warn("wg-quick not found; tunnel control and recovery are unavailable")
		}
	}
	d, err := service.New(opts)
	if err != nil {
		return err
	}

	authz := auth.NewAuthorizer(group, adminGroup, auth.SystemGroups)
	gid := authz.OperatorGID()
	if gid < 0 {
		log.Warn("operator group not found; only root can use the control socket", "group", group)
	}
	if dev {
		gid = -1
	}
	srv := &ipc.Server{Path: socketPath, SocketGID: gid, Auth: authz, Handler: d, Log: log}
	if err := srv.Listen(); err != nil {
		return fmt.Errorf("control socket: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		if err := srv.Serve(); err != nil {
			log.Error("control socket stopped", "err", err)
		}
	}()
	runDone := make(chan struct{})
	go func() {
		d.Run(ctx)
		close(runDone)
	}()
	sdNotify("READY=1")
	log.Info("wgmd ready", "socket", socketPath, "group", group, "uid", strconv.Itoa(os.Geteuid()), "user", currentUser())

	<-ctx.Done()
	sdNotify("STOPPING=1")
	log.Info("shutting down")
	srv.Shutdown(5 * time.Second)
	<-runDone
	return nil
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "?"
}

// sdNotify implements the systemd notification protocol (Type=notify).
func sdNotify(state string) {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return
	}
	if sock[0] == '@' {
		sock = "\x00" + sock[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		return
	}
	defer c.Close()
	c.Write([]byte(state))
}
