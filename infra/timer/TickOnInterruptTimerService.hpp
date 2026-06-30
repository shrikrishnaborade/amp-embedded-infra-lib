#ifndef INFRA_TICK_ON_INTERRUPT_TIMER_SERVICE_HPP
#define INFRA_TICK_ON_INTERRUPT_TIMER_SERVICE_HPP

#include "infra/timer/TimerService.hpp"

#if __has_include("esp_attr.h")
#include "esp_attr.h"
#else
#ifndef IRAM_ATTR
#define IRAM_ATTR
#endif
#endif

namespace infra
{
    class TickOnInterruptTimerService
        : public TimerService
    {
    public:
        TickOnInterruptTimerService(uint32_t id, Duration resolution);

        void NextTriggerChanged() override;
        TimePoint Now() const override;
        Duration Resolution() const override;

        void SetResolution(Duration resolution);

        void TimeProgressed(Duration amount);
        bool IRAM_ATTR SystemTickInterrupt();
        void ProcessDeferredFromInterrupt();

    private:
        void CalculateNextTrigger();
        void ProcessTicks();

    private:
        TimePoint systemTime = TimePoint();
        Duration resolution;

        volatile uint32_t ticksNextNotification{ 0 };
        volatile uint32_t ticksProgressed{ 0 };
        volatile bool notificationScheduled{ false };
    };
}

#endif
