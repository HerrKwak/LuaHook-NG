#pragma once

#define EXPORT				__declspec(dllexport)
#define REEXPORT_PROTO(x)	EXPORT static void x(); LPVOID lp##x
#define REEXPORT(x)			lp##x = GetProcAddress(hDLL, #x)
#define MAKE_FUNC(x)		void DllReExport::##x() \
							{ \
								reinterpret_cast<void(*)()>(self.lp##x)(); \
							}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID);

class DllReExport {
	static DllReExport self;
	HMODULE hDLL;
	DllReExport();

	REEXPORT_PROTO(AddIPAddress);
	REEXPORT_PROTO(AllocateAndGetInterfaceInfoFromStack);
	REEXPORT_PROTO(AllocateAndGetIpAddrTableFromStack);
	REEXPORT_PROTO(CancelIPChangeNotify);
	REEXPORT_PROTO(CancelMibChangeNotify2);
	REEXPORT_PROTO(CloseCompartment);
	REEXPORT_PROTO(CloseGetIPPhysicalInterfaceForDestination);
	REEXPORT_PROTO(ConvertCompartmentGuidToId);
	REEXPORT_PROTO(ConvertCompartmentIdToGuid);
	REEXPORT_PROTO(ConvertGuidToStringA);
	REEXPORT_PROTO(ConvertGuidToStringW);
	REEXPORT_PROTO(ConvertInterfaceAliasToLuid);
	REEXPORT_PROTO(ConvertInterfaceGuidToLuid);
	REEXPORT_PROTO(ConvertInterfaceIndexToLuid);
	REEXPORT_PROTO(ConvertInterfaceLuidToAlias);
	REEXPORT_PROTO(ConvertInterfaceLuidToGuid);
	REEXPORT_PROTO(ConvertInterfaceLuidToIndex);
	REEXPORT_PROTO(ConvertInterfaceLuidToNameA);
	REEXPORT_PROTO(ConvertInterfaceLuidToNameW);
	REEXPORT_PROTO(ConvertInterfaceNameToLuidA);
	REEXPORT_PROTO(ConvertInterfaceNameToLuidW);
	REEXPORT_PROTO(ConvertInterfacePhysicalAddressToLuid);
	REEXPORT_PROTO(ConvertIpv4MaskToLength);
	REEXPORT_PROTO(ConvertLengthToIpv4Mask);
	REEXPORT_PROTO(ConvertRemoteInterfaceAliasToLuid);
	REEXPORT_PROTO(ConvertRemoteInterfaceGuidToLuid);
	REEXPORT_PROTO(ConvertRemoteInterfaceIndexToLuid);
	REEXPORT_PROTO(ConvertRemoteInterfaceLuidToAlias);
	REEXPORT_PROTO(ConvertRemoteInterfaceLuidToGuid);
	REEXPORT_PROTO(ConvertRemoteInterfaceLuidToIndex);
	REEXPORT_PROTO(ConvertStringToGuidA);
	REEXPORT_PROTO(ConvertStringToGuidW);
	REEXPORT_PROTO(ConvertStringToInterfacePhysicalAddress);
	REEXPORT_PROTO(CreateAnycastIpAddressEntry);
	REEXPORT_PROTO(CreateIpForwardEntry);
	REEXPORT_PROTO(CreateIpForwardEntry2);
	REEXPORT_PROTO(CreateIpNetEntry);
	REEXPORT_PROTO(CreateIpNetEntry2);
	REEXPORT_PROTO(CreatePersistentTcpPortReservation);
	REEXPORT_PROTO(CreatePersistentUdpPortReservation);
	REEXPORT_PROTO(CreateProxyArpEntry);
	REEXPORT_PROTO(CreateSortedAddressPairs);
	REEXPORT_PROTO(CreateUnicastIpAddressEntry);
	REEXPORT_PROTO(DeleteAnycastIpAddressEntry);
	REEXPORT_PROTO(DeleteIPAddress);
	REEXPORT_PROTO(DeleteIpForwardEntry);
	REEXPORT_PROTO(DeleteIpForwardEntry2);
	REEXPORT_PROTO(DeleteIpNetEntry);
	REEXPORT_PROTO(DeleteIpNetEntry2);
	REEXPORT_PROTO(DeletePersistentTcpPortReservation);
	REEXPORT_PROTO(DeletePersistentUdpPortReservation);
	REEXPORT_PROTO(DeleteProxyArpEntry);
	REEXPORT_PROTO(DeleteUnicastIpAddressEntry);
	REEXPORT_PROTO(DisableMediaSense);
	REEXPORT_PROTO(EnableRouter);
	REEXPORT_PROTO(FlushIpNetTable);
	REEXPORT_PROTO(FlushIpNetTable2);
	REEXPORT_PROTO(FlushIpPathTable);
	REEXPORT_PROTO(FreeMibTable);
	REEXPORT_PROTO(GetAdapterIndex);
	REEXPORT_PROTO(GetAdapterOrderMap);
	REEXPORT_PROTO(GetAdaptersAddresses);
	REEXPORT_PROTO(GetAdaptersInfo);
	REEXPORT_PROTO(GetAnycastIpAddressEntry);
	REEXPORT_PROTO(GetAnycastIpAddressTable);
	REEXPORT_PROTO(GetBestInterface);
	REEXPORT_PROTO(GetBestInterfaceEx);
	REEXPORT_PROTO(GetBestRoute);
	REEXPORT_PROTO(GetBestRoute2);
	REEXPORT_PROTO(GetCurrentThreadCompartmentId);
	REEXPORT_PROTO(GetExtendedTcpTable);
	REEXPORT_PROTO(GetExtendedUdpTable);
	REEXPORT_PROTO(GetFriendlyIfIndex);
	REEXPORT_PROTO(GetIcmpStatistics);
	REEXPORT_PROTO(GetIcmpStatisticsEx);
	REEXPORT_PROTO(GetIfEntry);
	REEXPORT_PROTO(GetIfEntry2);
	REEXPORT_PROTO(GetIfStackTable);
	REEXPORT_PROTO(GetIfTable);
	REEXPORT_PROTO(GetIfTable2);
	REEXPORT_PROTO(GetIfTable2Ex);
	REEXPORT_PROTO(GetInterfaceInfo);
	REEXPORT_PROTO(GetInvertedIfStackTable);
	REEXPORT_PROTO(GetIpAddrTable);
	REEXPORT_PROTO(GetIpErrorString);
	REEXPORT_PROTO(GetIpForwardEntry2);
	REEXPORT_PROTO(GetIpForwardTable);
	REEXPORT_PROTO(GetIpForwardTable2);
	REEXPORT_PROTO(GetIpInterfaceEntry);
	REEXPORT_PROTO(GetIpInterfaceTable);
	REEXPORT_PROTO(GetIpNetEntry2);
	REEXPORT_PROTO(GetIpNetTable);
	REEXPORT_PROTO(GetIpNetTable2);
	REEXPORT_PROTO(GetIpNetworkConnectionBandwidthEstimates);
	REEXPORT_PROTO(GetIpPathEntry);
	REEXPORT_PROTO(GetIpPathTable);
	REEXPORT_PROTO(GetIpStatistics);
	REEXPORT_PROTO(GetIpStatisticsEx);
	REEXPORT_PROTO(GetMulticastIpAddressEntry);
	REEXPORT_PROTO(GetMulticastIpAddressTable);
	REEXPORT_PROTO(GetNetworkInformation);
	REEXPORT_PROTO(GetNetworkParams);
	REEXPORT_PROTO(GetNumberOfInterfaces);
	REEXPORT_PROTO(GetOwnerModuleFromPidAndInfo);
	REEXPORT_PROTO(GetOwnerModuleFromTcp6Entry);
	REEXPORT_PROTO(GetOwnerModuleFromTcpEntry);
	REEXPORT_PROTO(GetOwnerModuleFromUdp6Entry);
	REEXPORT_PROTO(GetOwnerModuleFromUdpEntry);
	REEXPORT_PROTO(GetPerAdapterInfo);
	REEXPORT_PROTO(GetPerTcp6ConnectionEStats);
	REEXPORT_PROTO(GetPerTcp6ConnectionStats);
	REEXPORT_PROTO(GetPerTcpConnectionEStats);
	REEXPORT_PROTO(GetPerTcpConnectionStats);
	REEXPORT_PROTO(GetRTTAndHopCount);
	REEXPORT_PROTO(GetSessionCompartmentId);
	REEXPORT_PROTO(GetTcp6Table);
	REEXPORT_PROTO(GetTcp6Table2);
	REEXPORT_PROTO(GetTcpStatistics);
	REEXPORT_PROTO(GetTcpStatisticsEx);
	REEXPORT_PROTO(GetTcpTable);
	REEXPORT_PROTO(GetTcpTable2);
	REEXPORT_PROTO(GetTeredoPort);
	REEXPORT_PROTO(GetUdp6Table);
	REEXPORT_PROTO(GetUdpStatistics);
	REEXPORT_PROTO(GetUdpStatisticsEx);
	REEXPORT_PROTO(GetUdpTable);
	REEXPORT_PROTO(GetUniDirectionalAdapterInfo);
	REEXPORT_PROTO(GetUnicastIpAddressEntry);
	REEXPORT_PROTO(GetUnicastIpAddressTable);
	REEXPORT_PROTO(Icmp6CreateFile);
	REEXPORT_PROTO(Icmp6ParseReplies);
	REEXPORT_PROTO(Icmp6SendEcho2);
	REEXPORT_PROTO(IcmpCloseHandle);
	REEXPORT_PROTO(IcmpCreateFile);
	REEXPORT_PROTO(IcmpParseReplies);
	REEXPORT_PROTO(IcmpSendEcho);
	REEXPORT_PROTO(IcmpSendEcho2);
	REEXPORT_PROTO(IcmpSendEcho2Ex);
	REEXPORT_PROTO(InitializeIpForwardEntry);
	REEXPORT_PROTO(InitializeIpInterfaceEntry);
	REEXPORT_PROTO(InitializeUnicastIpAddressEntry);
	REEXPORT_PROTO(InternalCleanupPersistentStore);
	REEXPORT_PROTO(InternalCreateAnycastIpAddressEntry);
	REEXPORT_PROTO(InternalCreateIpForwardEntry);
	REEXPORT_PROTO(InternalCreateIpForwardEntry2);
	REEXPORT_PROTO(InternalCreateIpNetEntry);
	REEXPORT_PROTO(InternalCreateIpNetEntry2);
	REEXPORT_PROTO(InternalCreateUnicastIpAddressEntry);
	REEXPORT_PROTO(InternalDeleteAnycastIpAddressEntry);
	REEXPORT_PROTO(InternalDeleteIpForwardEntry);
	REEXPORT_PROTO(InternalDeleteIpForwardEntry2);
	REEXPORT_PROTO(InternalDeleteIpNetEntry);
	REEXPORT_PROTO(InternalDeleteIpNetEntry2);
	REEXPORT_PROTO(InternalDeleteUnicastIpAddressEntry);
	REEXPORT_PROTO(InternalFindInterfaceByAddress);
	REEXPORT_PROTO(InternalGetAnycastIpAddressEntry);
	REEXPORT_PROTO(InternalGetAnycastIpAddressTable);
	REEXPORT_PROTO(InternalGetForwardIpTable2);
	REEXPORT_PROTO(InternalGetIPPhysicalInterfaceForDestination);
	REEXPORT_PROTO(InternalGetIfEntry2);
	REEXPORT_PROTO(InternalGetIfTable);
	REEXPORT_PROTO(InternalGetIfTable2);
	REEXPORT_PROTO(InternalGetIpAddrTable);
	REEXPORT_PROTO(InternalGetIpForwardEntry2);
	REEXPORT_PROTO(InternalGetIpForwardTable);
	REEXPORT_PROTO(InternalGetIpInterfaceEntry);
	REEXPORT_PROTO(InternalGetIpInterfaceTable);
	REEXPORT_PROTO(InternalGetIpNetEntry2);
	REEXPORT_PROTO(InternalGetIpNetTable);
	REEXPORT_PROTO(InternalGetIpNetTable2);
	REEXPORT_PROTO(InternalGetMulticastIpAddressEntry);
	REEXPORT_PROTO(InternalGetMulticastIpAddressTable);
	REEXPORT_PROTO(InternalGetRtcSlotInformation);
	REEXPORT_PROTO(InternalGetTcp6Table2);
	REEXPORT_PROTO(InternalGetTcp6TableWithOwnerModule);
	REEXPORT_PROTO(InternalGetTcp6TableWithOwnerPid);
	REEXPORT_PROTO(InternalGetTcpTable);
	REEXPORT_PROTO(InternalGetTcpTable2);
	REEXPORT_PROTO(InternalGetTcpTableEx);
	REEXPORT_PROTO(InternalGetTcpTableWithOwnerModule);
	REEXPORT_PROTO(InternalGetTcpTableWithOwnerPid);
	REEXPORT_PROTO(InternalGetTunnelPhysicalAdapter);
	REEXPORT_PROTO(InternalGetUdp6TableWithOwnerModule);
	REEXPORT_PROTO(InternalGetUdp6TableWithOwnerPid);
	REEXPORT_PROTO(InternalGetUdpTable);
	REEXPORT_PROTO(InternalGetUdpTableEx);
	REEXPORT_PROTO(InternalGetUdpTableWithOwnerModule);
	REEXPORT_PROTO(InternalGetUdpTableWithOwnerPid);
	REEXPORT_PROTO(InternalGetUnicastIpAddressEntry);
	REEXPORT_PROTO(InternalGetUnicastIpAddressTable);
	REEXPORT_PROTO(InternalIcmpCreateFileEx);
	REEXPORT_PROTO(InternalSetIfEntry);
	REEXPORT_PROTO(InternalSetIpForwardEntry);
	REEXPORT_PROTO(InternalSetIpForwardEntry2);
	REEXPORT_PROTO(InternalSetIpInterfaceEntry);
	REEXPORT_PROTO(InternalSetIpNetEntry);
	REEXPORT_PROTO(InternalSetIpNetEntry2);
	REEXPORT_PROTO(InternalSetIpStats);
	REEXPORT_PROTO(InternalSetTcpEntry);
	REEXPORT_PROTO(InternalSetTeredoPort);
	REEXPORT_PROTO(InternalSetUnicastIpAddressEntry);
	REEXPORT_PROTO(IpReleaseAddress);
	REEXPORT_PROTO(IpRenewAddress);
	REEXPORT_PROTO(LookupPersistentTcpPortReservation);
	REEXPORT_PROTO(LookupPersistentUdpPortReservation);
	REEXPORT_PROTO(NTPTimeToNTFileTime);
	REEXPORT_PROTO(NTTimeToNTPTime);
	REEXPORT_PROTO(NhGetGuidFromInterfaceName);
	REEXPORT_PROTO(NhGetInterfaceDescriptionFromGuid);
	REEXPORT_PROTO(NhGetInterfaceNameFromDeviceGuid);
	REEXPORT_PROTO(NhGetInterfaceNameFromGuid);
	REEXPORT_PROTO(NhpAllocateAndGetInterfaceInfoFromStack);
	REEXPORT_PROTO(NotifyAddrChange);
	REEXPORT_PROTO(NotifyCompartmentChange);
	REEXPORT_PROTO(NotifyIpInterfaceChange);
	REEXPORT_PROTO(NotifyRouteChange);
	REEXPORT_PROTO(NotifyRouteChange2);
	REEXPORT_PROTO(NotifyStableUnicastIpAddressTable);
	REEXPORT_PROTO(NotifyTeredoPortChange);
	REEXPORT_PROTO(NotifyUnicastIpAddressChange);
	REEXPORT_PROTO(OpenCompartment);
	REEXPORT_PROTO(ParseNetworkString);
	REEXPORT_PROTO(ResolveIpNetEntry2);
	REEXPORT_PROTO(ResolveNeighbor);
	REEXPORT_PROTO(RestoreMediaSense);
	REEXPORT_PROTO(SendARP);
	REEXPORT_PROTO(SetAdapterIpAddress);
	REEXPORT_PROTO(SetCurrentThreadCompartmentId);
	REEXPORT_PROTO(SetIfEntry);
	REEXPORT_PROTO(SetIpForwardEntry);
	REEXPORT_PROTO(SetIpForwardEntry2);
	REEXPORT_PROTO(SetIpInterfaceEntry);
	REEXPORT_PROTO(SetIpNetEntry);
	REEXPORT_PROTO(SetIpNetEntry2);
	REEXPORT_PROTO(SetIpStatistics);
	REEXPORT_PROTO(SetIpStatisticsEx);
	REEXPORT_PROTO(SetIpTTL);
	REEXPORT_PROTO(SetNetworkInformation);
	REEXPORT_PROTO(SetPerTcp6ConnectionEStats);
	REEXPORT_PROTO(SetPerTcp6ConnectionStats);
	REEXPORT_PROTO(SetPerTcpConnectionEStats);
	REEXPORT_PROTO(SetPerTcpConnectionStats);
	REEXPORT_PROTO(SetSessionCompartmentId);
	REEXPORT_PROTO(SetTcpEntry);
	REEXPORT_PROTO(SetUnicastIpAddressEntry);
	REEXPORT_PROTO(UnenableRouter);
	REEXPORT_PROTO(_PfAddFiltersToInterface);
	REEXPORT_PROTO(_PfAddGlobalFilterToInterface);
	REEXPORT_PROTO(_PfBindInterfaceToIPAddress);
	REEXPORT_PROTO(_PfBindInterfaceToIndex);
	REEXPORT_PROTO(_PfCreateInterface);
	REEXPORT_PROTO(_PfDeleteInterface);
	REEXPORT_PROTO(_PfDeleteLog);
	REEXPORT_PROTO(_PfGetInterfaceStatistics);
	REEXPORT_PROTO(_PfMakeLog);
	REEXPORT_PROTO(_PfRebindFilters);
	REEXPORT_PROTO(_PfRemoveFilterHandles);
	REEXPORT_PROTO(_PfRemoveFiltersFromInterface);
	REEXPORT_PROTO(_PfRemoveGlobalFilterFromInterface);
	REEXPORT_PROTO(_PfSetLogBuffer);
	REEXPORT_PROTO(_PfTestPacket);
	REEXPORT_PROTO(_PfUnBindInterface);
	REEXPORT_PROTO(do_echo_rep);
	REEXPORT_PROTO(do_echo_req);
	REEXPORT_PROTO(if_indextoname);
	REEXPORT_PROTO(if_nametoindex);
	REEXPORT_PROTO(register_icmp);
};
