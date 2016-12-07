%define nfcheck_version 0.1
%define nfcheck_release 1
Summary: Netflow drops monitor
Name: nfcheck
Version: %{nfcheck_version}
Release: %{nfcheck_release}


License: GPL
URL: http://www.tcpdump.org
Group: Applications/Internet
Source0: nfcheck-%{nfcheck_version}.tar.gz

Prefix: %{_prefix}
BuildRequires: libpcap-devel
Requires:	libpcap

%description
Netflow drops monitor collects netflow data chunks by monitoring
netflow stream consistence. It sends recevived chunks to head daemon
that analyzes all these chunks to detemine netflow data loss.

%package -n nfcheck
Version: %{nfcheck_version}
Release: %{nfcheck_release}
Summary: Nfcheck client
Group: Applications/Internet
License: GPL

%description -n nfcheck
Client part of netflow drops monitor

%package -n nfcold
Version: %{nfcheck_version}
Release: %{nfcheck_release}
Summary: Nfcheck server
Group: Applications/Internet
License: GPL

%description -n nfcold
Client part of netflow drops monitor

%prep
%setup -q -n snif

%build 
make 
make nfcold ARCH=x86

%install
rm -rf ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}%{_etcdir}
mkdir -p ${RPM_BUILD_ROOT}%{_sbindir}

make DESTDIR=${RPM_BUILD_ROOT} 	install
make DESTDIR=${RPM_BUILD_ROOT} nfcold_install

%clean
rm -rf ${RPM_BUILD_ROOT}


%post -n nfcheck
/sbin/chkconfig --add nfcheck

%preun -n nfcheck
if [ "$1" = "0" ]; then
	/sbin/service nfcheck stop > /dev/null 2>&1
	/sbin/chkconfig --del nfcheck
fi
exit 0

%post -n nfcold
/sbin/chkconfig --add nfcold

%preun -n nfcold
if [ "$1" = "0" ]; then
	/sbin/service nfcold stop > /dev/null 2>&1
	/sbin/chkconfig --del nfcold
fi
exit 0


%files -n nfcheck
%defattr(-,root,root)
%{_sbindir}/nfcheck
%{_etcdir}/init.d/nfcheck

%files -n nfcold
%defattr(-,root,root)
%{_sbindir}/nfcold
%{_etcdir}/init.d/nfcold

