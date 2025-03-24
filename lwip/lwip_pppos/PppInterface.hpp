#ifndef PPP_EVENTS_HPP_
#define PPP_EVENTS_HPP_

#include "infra/util/Observer.hpp"

namespace services
{
    class Ppp;

    enum class PppError : uint8_t
    {
        Success = 0,
        ConnectionTimeout,
        DisconnectFromPeer,
        AuthenticationFailure,
        ProtocolFailure,
        Unknown,
    };

    class PppObserver
        : public infra::Observer<PppObserver, Ppp>
    {
    protected:
        PppObserver() = default;
        PppObserver(const PppObserver& other) = delete;
        PppObserver& operator=(const PppObserver& other) = delete;
        ~PppObserver() = default;

    public:
        virtual void Connected() = 0;
        virtual void Disconnected() = 0;
        virtual void Error(PppError error) = 0;
    };

    class Ppp
        : public infra::Subject<PppObserver>
    {
    public:
        virtual void Connect() = 0;
        virtual void Disconnect() = 0;
    };
};
#endif
