#pragma once
#include "pch.h"
#include "Wintun.g.h"
#include "lwip\init.h"
#include "lwip\netif.h"
#include "lwip\timeouts.h"
#include "lwip\ip.h"
#include "lwip\tcp.h"
#include "lwip\udp.h"
#include "winrt/Windows.Storage.Streams.h"
#include "TcpSocket.h"

namespace winrt::Wintun2socks::implementation
{
    struct Wintun : WintunT<Wintun>
    {
    private:
        const uint32_t DNS_ADDRESS = 0x01010101U;
        const uint16_t DNS_PORT = 53;
        static winrt::com_ptr<Wintun> m_instance;
        static netif* m_interface;
        static tcp_pcb* m_listenPCB;
        static err_t Wintun::outputPCB (struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);
        winrt::event<PacketPopedHandler> m_packetPoped;

    public:
        Wintun() = default;

        static Wintun2socks::Wintun Instance();
        void Init();
        void Deinit();
        void CheckTimeout();
        uint8_t PushPacket(array_view<uint8_t const> packet);
        uint8_t PushDnsPayload(uint32_t addr, uint16_t port, Windows::Storage::Streams::IBuffer const& data);
        uint8_t PushUdpPayload(uint32_t src_addr, uint16_t src_port, uint32_t dst_addr, uint16_t dst_port, uint64_t packet, uint16_t packetLen);
        winrt::event_token PacketPoped(Wintun2socks::PacketPopedHandler const& handler);
        void PacketPoped(winrt::event_token const& token) noexcept;
    };
}
namespace winrt::Wintun2socks::factory_implementation
{
    struct Wintun : WintunT<Wintun, implementation::Wintun>
    {
    };
}
