#ifndef SERVICES_MQTT_MULTIPLE_ACCESS_HPP
#define SERVICES_MQTT_MULTIPLE_ACCESS_HPP

#include "services/network/Mqtt.hpp"
#include "infra/event/ClaimableResource.hpp"
#include "infra/util/IntrusiveForwardList.hpp"

namespace services
{
    class MqttMultipleAccess;

    class MqttMultipleAccessMaster                                                                             //TICS !OOP#013
        : public MqttClientObserver
        , public infra::ClaimableResource
    {
    public:
        void Register(MqttMultipleAccess& access);
        void Unregister(MqttMultipleAccess& access);
        void Publish(MqttMultipleAccess& access);
        void Subscribe(MqttMultipleAccess& access);
        void NotificationDone();
        void ReleaseActive();

        // Implementation of MqttClientObserver
        virtual void Attached() override;
        virtual void PublishDone() override;
        virtual void SubscribeDone() override;
        virtual infra::SharedPtr<infra::StreamWriter> ReceivedNotification(infra::BoundedConstString topic, uint32_t payloadSize) override;
        virtual void Detaching() override;
        virtual void FillTopic(infra::StreamWriter& writer) const override;
        virtual void FillPayload(infra::StreamWriter& writer) const override;

    private:
        infra::IntrusiveForwardList<MqttMultipleAccess> accesses;
        MqttMultipleAccess* active = nullptr;
    };

    class MqttMultipleAccess
        : public MqttClient
        , public infra::IntrusiveForwardList<MqttMultipleAccess>::NodeType
    {
    public:
        explicit MqttMultipleAccess(MqttMultipleAccessMaster& master);
        ~MqttMultipleAccess();

        // Implementation of MqttClient
        virtual void Publish() override;
        virtual void Subscribe() override;
        virtual void NotificationDone() override;

        void Attached();
        void PublishDone();
        void SubscribeDone();
        infra::SharedPtr<infra::StreamWriter> ReceivedNotification(infra::BoundedConstString topic, uint32_t payloadSize);
        void Detaching();
        void FillTopic(infra::StreamWriter& writer) const;
        void FillPayload(infra::StreamWriter& writer) const;

    private:
        MqttMultipleAccessMaster& master;
        infra::ClaimableResource::Claimer claimer;
    };
}

#endif
