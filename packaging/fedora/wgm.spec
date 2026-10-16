# Build with:  make vendor-tarball VERSION=0.1.0
#              cp packaging/fedora/wgm.sysusers .
#              rpmbuild -ba packaging/fedora/wgm.spec --define "_sourcedir $PWD"
# The source tarball includes vendored Go modules so the build is offline and
# reproducible from go.sum.

Name:           wgm
Version:        0.1.0
Release:        1%{?dist}
Summary:        WireGuard manager daemon with health monitoring and kill switch
License:        MIT
URL:            https://github.com/cmerk2021/wgm
Source0:        %{name}-%{version}.tar.gz
Source1:        wgm.sysusers

BuildRequires:  golang >= 1.24
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  systemd-rpm-macros
# Fyne (wgm-ui) needs OpenGL, X11 and Wayland development headers.
BuildRequires:  mesa-libGL-devel
BuildRequires:  libX11-devel
BuildRequires:  libXcursor-devel
BuildRequires:  libXrandr-devel
BuildRequires:  libXinerama-devel
BuildRequires:  libXi-devel
BuildRequires:  libXxf86vm-devel
BuildRequires:  libxkbcommon-devel
BuildRequires:  wayland-devel

Requires:       wireguard-tools
Requires:       nftables
Requires:       iproute
%{?sysusers_requires_compat}

%description
wgmd is a privileged daemon that discovers existing WireGuard configurations
in /etc/wireguard, monitors tunnel health with explicit, testable rules,
performs bounded automatic recovery of tunnels it is authorised to manage, and
optionally enforces an nftables kill switch. It is controlled over an
authenticated local Unix socket.

%package ui
Summary:        Desktop client for the WGM WireGuard manager
Requires:       %{name} = %{version}-%{release}

%description ui
wgm-ui is an unprivileged Fyne desktop application that shows tunnel health,
throughput graphs, recovery progress and kill-switch state, and lets members
of the "wgm" group connect and disconnect WGM-managed tunnels.

%prep
%autosetup

%build
export GOFLAGS="-mod=vendor -trimpath"
export CGO_CFLAGS="%{optflags}" CGO_LDFLAGS="%{build_ldflags}"
make build VERSION=%{version} GOFLAGS="$GOFLAGS -buildmode=pie"

%check
export GOFLAGS="-mod=vendor"
go test ./internal/... ./ui/...

%install
make install DESTDIR=%{buildroot} PREFIX=%{_prefix} UNITDIR=%{_unitdir} SYSUSERSDIR=%{_sysusersdir} VERSION=%{version}

%pre
%sysusers_create_compat %{SOURCE1}

%post
%systemd_post wgmd.service wgm-killswitch.service

%preun
%systemd_preun wgmd.service wgm-killswitch.service
if [ "$1" -eq 0 ]; then
    # Package removal (not upgrade): remove the kill switch so the machine is
    # not left without network access once the tools to disable it are gone.
    %{_bindir}/wgmd killswitch-disable >/dev/null 2>&1 || :
fi

%postun
%systemd_postun_with_restart wgmd.service

%files
%license LICENSE
%doc README.md docs/
%{_bindir}/wgmd
%{_unitdir}/wgmd.service
%{_unitdir}/wgm-killswitch.service
%{_sysusersdir}/wgm.conf

%files ui
%{_bindir}/wgm-ui
%{_datadir}/applications/io.github.cmerk2021.wgm.desktop

%changelog
* Fri Oct 16 2026 WGM developers - 0.1.0-1
- Initial package
