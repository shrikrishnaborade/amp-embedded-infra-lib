#include "lwip/lwip_pppos/PppFacade.hpp"
#include "infra/stream/StreamManipulators.hpp"
#include "infra/util/ByteRange.hpp"
#include "lwip/dns.h"
#include "lwip/err.h"
#include "lwip/lwip_pppos/PppInterface.hpp"
#include "lwip/netif.h"
#include <cassert>
#include <chrono>
#include <cstddef>

namespace services
{
    PppFacade::PppFacade(services::Tracer& tracer, hal::SerialCommunication& usart, netif& ppposNetif, infra::MemoryRange<uint8_t> initialLCPData)
        : tracer(tracer)
        , usart(usart)
        , ppposNetif(ppposNetif)
        , receivedData([this]()
              {
                  while (!receivedData.Empty())
                  {
                      auto data = receivedData.ContiguousRange();
                      HandleReceivedData(data);
                      receivedData.Consume(static_cast<uint32_t>(data.size()));
                  }
              })
        , streamWriterOnSerialCommunication(txBuffer, usart)
        , writeStream(streamWriterOnSerialCommunication)
        , initialLcpData(initialLCPData)
    {
        ppp = pppos_create(&ppposNetif, WriteData, LinkStatus, this);
        assert(ppp != nullptr);

        ppp_set_auth(ppp, PPPAUTHTYPE_ANY, "PAPUSER", "");
        ppp_set_auth_required(ppp, 0);
        ppp_set_usepeerdns(ppp, 1);
        ppp_set_listen_time(ppp, 100u);

        usart.ReceiveData([this](infra::ConstByteRange data)
            {
                receivedData.AddFromInterrupt(data);
            });
    }

    PppFacade::~PppFacade()
    {
        if (ppp)
            ppp_free(ppp);
    }

    void PppFacade::Connect()
    {
        auto status = ppp_listen(ppp);
        assert(status == ERR_OK);

        // This is specifically applicable to Ublox modem, where first LCP request is received together with CONNECT response from modem
        if (!initialLcpData.empty())
        {
            pppos_input(ppp, initialLcpData.begin(), initialLcpData.size());
        }
    }

    void PppFacade::Disconnect()
    {
        ppp_close(ppp, 0);
    }

    ///
    // Internal implementation
    ///
    uint32_t PppFacade::WriteData(ppp_pcb* pcb, const void* data, uint32_t len, void* ctx)
    {
        auto c = static_cast<PppFacade*>(ctx);
        return c->Write(pcb, data, len);
    }

    void PppFacade::LinkStatus(ppp_pcb* pcb, int errorCode, void* ctx)
    {
        auto c = static_cast<PppFacade*>(ctx);
        c->LinkStatusIndication(pcb, errorCode);
    }

    void PppFacade::LinkStatusIndication(ppp_pcb* pcb, int errorCode)
    {
        const struct netif* pppif = ppp_netif(pcb);
        switch (errorCode)
        {
            case PPPERR_NONE: /* No error. */
            {
#if LWIP_DNS
                const ip_addr_t* ns;
#endif /* LWIP_DNS */
                tracer.Trace() << "PPP Link Status: PPPERR_NONE" << infra::endl;
#if LWIP_IPV4
                tracer.Trace() << "IP address: " << ip4addr_ntoa(netif_ip4_addr(pppif)) << infra::endl;
                tracer.Trace() << "peer IP address: " << ip4addr_ntoa(netif_ip4_gw(pppif)) << infra::endl;
                tracer.Trace() << "netmask: " << ip4addr_ntoa(netif_ip4_netmask(pppif)) << infra::endl;
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
                tracer.Trace() << "IP address: " << ip6addr_ntoa(netif_ip6_addr(pppif, 0)) << infra::endl;
#endif /* LWIP_IPV6 */

#if LWIP_DNS
                ns = dns_getserver(0);
                tracer.Trace() << "DNS1: " << ipaddr_ntoa(ns) << infra::endl;
                ns = dns_getserver(1);
                tracer.Trace() << "DNS2: " << ipaddr_ntoa(ns) << infra::endl;
#endif /* LWIP_DNS */

#if PPP_IPV6_SUPPORT
                tracer.Trace() << "IPv6 address: " << ip6addr_ntoa(netif_ip6_addr(pppif, 0)) << infra::endl
                               << infra::endl;
#endif /* PPP_IPV6_SUPPORT */

                if (netif_is_up(pppif) && (pppif->ip_addr.u_addr.ip4.addr != 0))
                {
                    SubjectType::NotifyObservers([this](auto& obs)
                        {
                            obs.Connected();
                        });
                }
            }
            break;

            case PPPERR_PARAM: /* Invalid parameter. */
                tracer.Trace() << "ppp_link_status_cb: PPPERR_PARAM" << infra::endl;
                assert(false);
                break;

            case PPPERR_OPEN: /* Unable to open PPP session. */
                tracer.Trace() << "ppp_link_status_cb: PPPERR_OPEN" << infra::endl;
                assert(false);
                break;

            case PPPERR_DEVICE: /* Invalid I/O device for PPP. */
                tracer.Trace() << "ppp_link_status_cb: PPPERR_DEVICE" << infra::endl;
                assert(false);
                break;

            case PPPERR_ALLOC: /* Unable to allocate resources. */
                tracer.Trace() << "ppp_link_status_cb: PPPERR_ALLOC" << infra::endl;
                assert(false);
                break;

            case PPPERR_USER: /* User interrupt to initiate clouser. */
                tracer.Trace() << "ppp_link_status_cb: PPPERR_USER" << infra::endl;

                ppp_free(this->ppp);
                ppp = nullptr;

                // Wait till modem exits ppp mode and enter AT state by sending \r\nOK\r\n
                // Max wait is 5 seconds, but this timer is also triggered as soon as OK is received from modem
                waitTimer.Start(std::chrono::seconds(5u), [this]()
                    {
                        SubjectType::NotifyObservers([this](auto& obs)
                            {
                                obs.Disconnected();
                            });
                    });
                break;

            case PPPERR_CONNECT: /* Connection lost either due to modem disconnected/rebooted/sent a formal terminate request. */
                tracer.Trace() << "ppp_link_status_cb: PPPERR_CONNECT" << infra::endl;
                ppp_free(this->ppp);
                ppp = nullptr;

                SubjectType::NotifyObservers([this](auto& obs)
                    {
                        obs.Error(PppError::DisconnectFromPeer);
                    });
                break;

            case PPPERR_AUTHFAIL: /* Failed authentication challenge. */
                tracer.Trace() << "ppp_link_status_cb: PPPERR_AUTHFAIL" << infra::endl;
                SubjectType::NotifyObservers([this](auto& obs)
                    {
                        obs.Error(PppError::AuthenticationFailure);
                    });
                break;

            case PPPERR_PROTOCOL: /* Failed to meet protocol. */
                tracer.Trace() << "ppp_link_status_cb: PPPERR_PROTOCOL" << infra::endl;
                SubjectType::NotifyObservers([this](auto& obs)
                    {
                        obs.Error(PppError::ProtocolFailure);
                    });
                break;

            case PPPERR_PEERDEAD: /* Connection timeout. */
                tracer.Trace() << "ppp_link_status_cb: PPPERR_PEERDEAD" << infra::endl;
                SubjectType::NotifyObservers([this](auto& obs)
                    {
                        obs.Error(PppError::ConnectionTimeout);
                    });
                break;

            case PPPERR_IDLETIMEOUT: /* Idle Timeout. */
                tracer.Trace() << "ppp_link_status_cb: PPPERR_IDLETIMEOUT" << infra::endl;
                SubjectType::NotifyObservers([this](auto& obs)
                    {
                        obs.Error(PppError::ConnectionTimeout);
                    });
                break;

            case PPPERR_CONNECTTIME: /* PPPERR_CONNECTTIME. */
                tracer.Trace() << "ppp_link_status_cb: PPPERR_CONNECTTIME" << infra::endl;
                SubjectType::NotifyObservers([this](auto& obs)
                    {
                        obs.Error(PppError::ConnectionTimeout);
                    });
                break;

            case PPPERR_LOOPBACK: /* Connection timeout. */
                tracer.Trace() << "ppp_link_status_cb: PPPERR_LOOPBACK" << infra::endl;
                SubjectType::NotifyObservers([this](auto& obs)
                    {
                        obs.Error(PppError::ConnectionTimeout);
                    });
                break;

            default:
                tracer.Trace() << "ppp_link_status_cb: unknown errCode " << errorCode << infra::endl;
                SubjectType::NotifyObservers([this](auto& obs)
                    {
                        obs.Error(PppError::Unknown);
                    });
                break;
        }
    }

    uint32_t PppFacade::Write(ppp_pcb* pcb, const void* data, uint32_t len)
    {
        auto d = static_cast<uint8_t*>(const_cast<void*>(data));
        auto range = infra::MemoryRange<uint8_t>(d, d + len);
        // this->tracer.Trace() << "PPP: usart tx " << infra::AsHex(range) << infra::endl;
        writeStream << range;
        return len;
    }

    void PppFacade::HandleReceivedData(infra::ConstByteRange data)
    {
        // Check if data contains termination character sequence, which indicates that modem is back to AT mode
        std::array<uint8_t, 2u> pattern{ 0x0d, 0x0a };
        auto it = std::search(data.begin(), data.end(), pattern.begin(), pattern.end());
        if (it != data.end())
        {
            this->tracer.Trace() << "PPP: usart rx " << infra::AsHex(data) << infra::endl;

            // If wait timer is armed on PPP terminate confirmation, trigger it now, as modem is back to AT mode.
            if (waitTimer.Armed())
            {
                // Clear to queue
                // receivedData.Consume(receivedData.Size());

                waitTimer.Cancel();
                waitTimer.Start(std::chrono::milliseconds(200), [this]()
                    {
                        SubjectType::NotifyObservers([this](auto& obs)
                            {
                                obs.Disconnected();
                            });
                    });
                return;
            }
        }
        // Feed received data only if PPP context is valid
        if (ppp)
        {
            pppos_input(ppp, data.begin(), data.size());
        }
    }
}
