#ifndef SERVICES_GAP_CENTRAL_MOCK_HPP
#define SERVICES_GAP_CENTRAL_MOCK_HPP

#include "services/ble/Gap.hpp"
#include "gmock/gmock.h"

namespace services
{
    class GapCentralMock
        : public GapCentral
    {
    public:
        MOCK_METHOD(void, Connect, (hal::MacAddress macAddress, GapDeviceAddressType addressType));
        MOCK_METHOD(void, Disconnect, ());
        MOCK_METHOD(void, SetAddress, (hal::MacAddress macAddress, GapDeviceAddressType addressType));
        MOCK_METHOD(void, StartDeviceDiscovery, ());
        MOCK_METHOD(void, StopDeviceDiscovery, ());
        MOCK_METHOD(bool, IsPeerDeviceBonded, (services::GapAdvertisingEventAddressType addressType, hal::MacAddress macAddress));
        MOCK_METHOD(void, GetPeerDevicePrivateAddress, (hal::MacAddress randomMacAddress, hal::MacAddress& privateMacAddress));
    };
}

#endif
