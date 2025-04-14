#ifndef DIAL_UP_MODEM_STATUS_HPP_
#define DIAL_UP_MODEM_STATUS_HPP_

#include "infra/util/Observer.hpp"

namespace services
{
    class DialConnection;

    enum class DialConnectionError : uint8_t
    {
        Success = 0,
        ConnectionTimeout,
        Unknown,
    };

    class DialUpModemObserver
        : public infra::Observer<DialUpModemObserver, DialConnection>
    {
    protected:
        using infra::Observer<DialUpModemObserver, DialConnection>::Observer;

    public:
        virtual void Connected() = 0;
        virtual void Disconnected() = 0;
        virtual void Error(DialConnectionError error) = 0;
    };

    class DialConnection
        : public infra::Subject<DialUpModemObserver>
    {
    public:
        virtual void Dial() = 0;
        virtual void Disconnect() = 0;
    };
};
#endif
