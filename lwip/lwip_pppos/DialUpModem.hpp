#ifndef PPP_APPLICATION_HPP
#define PPP_APPLICATION_HPP

#include "hal/interfaces/SerialCommunication.hpp"
#include "infra/timer/Timer.hpp"
#include "infra/util/AutoResetFunction.hpp"
#include "infra/util/InterfaceConnector.hpp"
#include "infra/util/Optional.hpp"
#include "infra/util/PolymorphicVariant.hpp"
#include "lwip/lwip_pppos/DialUpModemStatus.hpp"
#include "lwip/lwip_pppos/PppFacade.hpp"
#include "lwip/lwip_pppos/PppInterface.hpp"
#include "netif/ppp/pppos.h"
#include "services/tracer/Tracer.hpp"
#include <cstdint>

// PPP facade based application, which basically initiates PPP connection to modem, and waits till either it is completed or failed.
namespace services
{
    class DialUpModem
        : public DialConnection
        , public infra::InterfaceConnector<DialUpModem>
        , public PppObserver
    {
    public:
        DialUpModem(services::Tracer& tracer, hal::SerialCommunication& modemUart);
        ~DialUpModem() = default;
        void NetifStatusIndication(struct netif* nif);

        // DialConnection
        void Dial() override;
        void Disconnect() override;

        // PppObserver
        void Connected() override;
        void Disconnected() override;
        void Error(PppError error) override;

        void KillModem();

    private:
        services::Tracer& tracer;
        struct netif pppNetIf;
        hal::SerialCommunication& modemUart;
        infra::TimerSingleShot timer;
        infra::TimerRepeating sysCheckTimer;
        infra::AutoResetFunction<void()> onDone;

        infra::Optional<PppFacade> pppState;
        infra::BoundedString::WithStorage<256u> additionalData;

        void DestroyPppMode();
        void CreatePppMode();

        void NotifyConnected();
        void NotifyDisconnected();

    private:
        class StateBase
        {
        public:
            explicit StateBase(DialUpModem& parent);
            StateBase(const StateBase&) = delete;
            StateBase& operator=(const StateBase&) = delete;
            virtual ~StateBase() = default;

            virtual void Connect() = 0;
            virtual void Disconnect() = 0;

            virtual void PppConnected() = 0;
            virtual void PppDisconnected() = 0;
            virtual void PppError() = 0;

        protected:
            DialUpModem& parent;
            infra::TimerSingleShot timer;
        };

        class StateIdle
            : public StateBase
        {
        public:
            explicit StateIdle(DialUpModem& parent);
            StateIdle(const StateIdle&) = delete;
            StateIdle& operator=(const StateIdle&) = delete;
            virtual ~StateIdle() = default;

            void Connect() override;
            void Disconnect() override {};

            void PppConnected() override {};
            void PppDisconnected() override {};
            void PppError() override {};
        };

        class StateConnecting
            : public StateBase
        {
        public:
            explicit StateConnecting(DialUpModem& parent);
            StateConnecting(const StateConnecting&) = delete;
            StateConnecting& operator=(const StateConnecting&) = delete;
            virtual ~StateConnecting() = default;

            void Connect() override {};
            void Disconnect() override {};

            void PppConnected() override;
            void PppDisconnected() override;
            void PppError() override;
        };

        class StateConnected
            : public StateBase
        {
        public:
            explicit StateConnected(DialUpModem& parent);
            StateConnected(const StateConnected&) = delete;
            StateConnecting& operator=(const StateConnected&) = delete;
            virtual ~StateConnected() = default;

            void Connect() override {};
            void Disconnect() override;

            void PppConnected() override {};
            void PppDisconnected() override {};
            void PppError() override;
        };

        class StateDisconnecting
            : public StateBase
        {
        public:
            explicit StateDisconnecting(DialUpModem& parent);
            StateDisconnecting(const StateDisconnecting&) = delete;
            StateConnecting& operator=(const StateDisconnecting&) = delete;
            virtual ~StateDisconnecting() = default;

            void Connect() override {};
            void Disconnect() override {};

            void PppConnected() override {};
            void PppDisconnected() override;
            void PppError() override {};
        };

        class StateDisconnected
            : public StateBase
        {
        public:
            explicit StateDisconnected(DialUpModem& parent);
            StateDisconnected(const StateDisconnected&) = delete;
            StateDisconnected& operator=(const StateDisconnected&) = delete;
            virtual ~StateDisconnected() = default;

            void Connect() override {};
            void Disconnect() override {};

            void PppConnected() override {};
            void PppDisconnected() override {};
            void PppError() override {};
        };

        class StateConnectionError
            : public StateBase
        {
        public:
            explicit StateConnectionError(DialUpModem& parent);
            StateConnectionError(const StateConnectionError&) = delete;
            StateConnectionError& operator=(const StateDisconnected&) = delete;
            virtual ~StateConnectionError() = default;

            void Connect() override {};
            void Disconnect() override {};

            void PppConnected() override {};
            void PppDisconnected() override {};
            void PppError() override {};
        };

        template<class T>
        void ToState()
        {
            state.Emplace<T>(*this);
        }

        infra::PolymorphicVariant<StateBase, StateIdle, StateConnecting, StateConnected, StateDisconnecting, StateDisconnected, StateConnectionError> state;

        void InitiateConnect();
    };
};

#endif
