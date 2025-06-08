#ifdef EMIL_HOST_BUILD
#include "infra/stream/IoOutputStream.hpp"
#endif
#include "services/tracer/Tracer.hpp"

namespace services
{
    namespace
    {
        Tracer* globalTracerInstance = nullptr;
        Tracer* globalSoftTracerInstance = nullptr;

#ifdef EMIL_HOST_BUILD
        infra::IoOutputStream ioOutputStream;
        TracerToStream tracerDummy(ioOutputStream);
#endif
    }

    void SetGlobalTracerInstance(Tracer& tracer)
    {
        assert(globalTracerInstance == nullptr);
        globalTracerInstance = &tracer;
    }

    Tracer& GlobalTracer()
    {
#ifdef EMIL_HOST_BUILD
        if (globalTracerInstance == nullptr)
            return tracerDummy;
#endif

        assert(globalTracerInstance != nullptr);
        return *globalTracerInstance;
    }

    void SetGlobalSoftTracerInstance(Tracer& tracer)
    {
        assert(globalSoftTracerInstance == nullptr);
        globalSoftTracerInstance = &tracer;
    }

    Tracer& GlobalSoftTracer()
    {
#ifdef EMIL_HOST_BUILD
        if (globalTracerInstance == nullptr)
            return tracerDummy;
#endif

        assert(globalSoftTracerInstance != nullptr);
        return *globalSoftTracerInstance;
    }
}
