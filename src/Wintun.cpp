#include "pch.h"
#include "Wintun.h"
#include "Wintun.g.cpp"

namespace winrt::Wintun2socks::implementation
{
    winrt::com_ptr<Wintun> Wintun::m_instance = winrt::make_self<Wintun>();
    netif* Wintun::m_interface = netif_default;
    tcp_pcb* Wintun::m_listenPCB = nullptr;
    const ip4_addr_t m_ip = { 0xC0A80301U };
    const ip4_addr_t m_mask = { 0x00000000U };

    err_t Wintun::outputPCB(netif* netif, pbuf* p, const ip4_addr_t* ipaddr)
    {
        if (p == NULL) return ERR_OK;
        auto arr = std::vector<uint8_t>(p->tot_len);
        pbuf_copy_partial(p, arr.data(), p->tot_len, 0);
        m_instance->m_packetPoped(*m_instance, arr);
        return ERR_OK;
    }
    Wintun2socks::Wintun Wintun::Instance()
    {
        return *m_instance;
    }
    void Wintun::Init()
    {
        if (m_listenPCB != nullptr) {
            return;
        }
        lwip_init();

        // add a listening pcb for TCP
        auto pcb = tcp_new();
        auto addr = ip_addr_any;
        tcp_bind(pcb, &addr, 0);
        pcb = tcp_listen_with_backlog(pcb, (UINT)TCP_DEFAULT_LISTEN_BACKLOG);
        Wintun::m_listenPCB = pcb;
        tcp_accept(pcb, (tcp_accept_fn)[](void* arg, tcp_pcb* newpcb, err_t err) -> err_t {
            auto socket = winrt::make<TcpSocket>(newpcb);
            TcpSocket::m_establishedTcp(socket);
            return ERR_OK;
        });
        m_interface = (struct netif*)malloc(sizeof(struct netif));
        if (m_interface == nullptr) {
            throw L"Cannot initialize a netif";
        }
        netif_add(m_interface, &m_mask, &m_mask, IP_ADDR_ANY, NULL, NULL, &ip_input);
        netif_set_up(m_interface);
        netif_set_link_up(m_interface);
        netif_set_default(m_interface);
        m_interface->mtu = 1500;
        m_interface->output = (netif_output_fn)&Wintun::outputPCB;
        m_interface->input = &ip_input;
    }
    void Wintun::Deinit()
    {
        TcpSocket::Deinit();
    }
    void Wintun::CheckTimeout()
    {
        sys_check_timeouts();
    }
    uint8_t Wintun::PushPacket(array_view<uint8_t const> packet)
    {
        // Call site ensures that ip protocol is TCP
        pbuf* p = pbuf_alloc(PBUF_RAW, packet.size(), PBUF_RAM);
        if (p == NULL) {
            // Drop it
            return 1;
        }
        memcpy_s(p->payload, p->len, packet.data(), packet.size());
        p->len = p->tot_len = packet.size();
        auto ret = m_interface->input(p, m_interface);
        return ret;
    }
    uint8_t Wintun::PushDnsPayload(uint32_t addr, uint16_t port, Windows::Storage::Streams::IBuffer const& data)
    {
        return PushUdpPayload(DNS_ADDRESS, DNS_PORT, addr, port, (IntPtrAbi)data.data(), data.Length());
    }
    uint8_t Wintun::PushUdpPayload(uint32_t src_addr, uint16_t src_port, uint32_t dst_addr, uint16_t dst_port, uint64_t packet, uint16_t packetLen)
    {
        auto p = pbuf_alloc(PBUF_TRANSPORT, packetLen, PBUF_REF);
        if (p == NULL) {
            return 1;
        }
        // memcpy_s(p->payload, packet->Length, packet->Data, packet->Length);
        p->payload = (void*)packet;
        p->len = p->tot_len = packetLen;
        ip_addr_t ip_src = { src_addr }, ip_dest = { dst_addr };
        auto ret = udp_sendto_if_src_dst(p, &ip_dest, dst_port, &ip_src, src_port);
        pbuf_free(p);
        return ret;
    }
    winrt::event_token Wintun::PacketPoped(Wintun2socks::PacketPopedHandler const& handler)
    {
        return m_packetPoped.add(handler);
    }
    void Wintun::PacketPoped(winrt::event_token const& token) noexcept
    {
        m_packetPoped.remove(token);
    }
}
extern "C" {
	void handle_assert_error(char* message, int result) {
		std::string s(message);
		std::wstring ws(s.begin(), s.end());
        throw ws;
	}
}

