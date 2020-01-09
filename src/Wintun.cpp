#include "Wintun.h"
#include <string>
#include <ppltasks.h>

using namespace concurrency;

namespace Wintun2socks {
	Wintun^ Wintun::m_instance = ref new Wintun();
	netif* Wintun::m_interface = netif_default;
	tcp_pcb* Wintun::m_listenPCB;
	udp_pcb* Wintun::m_dnsPCB;
	// const ip4_addr_t m_ip = { 0xC0A80301U };
	const ip4_addr_t m_dns = { 0x01010101U };
	const ip4_addr_t m_mask = { 0x00000000U };
	bool Wintun::running = false;
	err_t Wintun::outputPCB(struct netif *netif, struct pbuf *p,
		const ip4_addr_t *ipaddr) {
		if (p == NULL) return ERR_OK;
		auto arr = ref new Platform::Array<byte, 1>(p->tot_len);
		pbuf_copy_partial(p, arr->Data, p->tot_len, 0);
		m_instance->PacketPoped(m_instance, arr);
		return ERR_OK;
	}

	err_t(Wintun::recvUdp)(void * arg, udp_pcb * pcb, pbuf * p, const ip_addr_t * addr, u16_t port)
	{
		if (pcb->local_port == 53 && pcb->local_ip.addr == m_dns.addr) {
			auto arr = ref new Platform::Array<uint8, 1u>(p->tot_len);
			pbuf_copy_partial(p, arr->begin(), p->tot_len, 0);
			m_instance->DnsPacketPoped(m_instance, arr, addr->addr, port);
		}
		pbuf_free(p);
		return ERR_OK;
	}

	void Wintun::Init() {
		if (running) {
			return;
		}
		running = true;
		lwip_init();

		// add a listening pcb for TCP
		auto pcb = tcp_new();
		auto addr = ip_addr_any;
		tcp_bind(pcb, &addr, 0);
		pcb = tcp_listen_with_backlog(pcb, (UINT)TCP_DEFAULT_LISTEN_BACKLOG);
		Wintun::m_listenPCB = pcb;
		tcp_accept(pcb, (tcp_accept_fn)&TcpSocket::tcpAcceptFn);
		m_interface = (struct netif *)malloc(sizeof(struct netif));
		netif_add(m_interface, &m_mask, &m_mask, IP_ADDR_ANY, NULL, NULL, &ip_input);
		netif_set_up(m_interface);
		netif_set_link_up(m_interface);
		netif_set_default(m_interface);
		m_interface->mtu = 1500;
		m_interface->output = (netif_output_fn)&Wintun::outputPCB;
		m_interface->input = &ip_input;

		// UDP pcb for DNS
		m_dnsPCB = udp_new();
		udp_bind(m_dnsPCB, &m_dns, 53);
		udp_recv(m_dnsPCB, (udp_recv_fn)&Wintun::recvUdp, NULL);
	}

	void Wintun::Deinit() {
		TcpSocket::Deinit();
	}

	void Wintun::CheckTimeout()
	{
		sys_check_timeouts();
	}

	Wintun^ Wintun::Instance::get() {
		return Wintun::m_instance;
	}
	uint8 Wintun::PushPacket(const Platform::Array<uint8, 1u>^ packet) {
		// Check L4 protocol
		uint8_t proto = packet[9];
		if (proto != IP_PROTO_TCP && proto != IP_PROTO_UDP) {
			return 1;
		}
		pbuf* p = pbuf_alloc(PBUF_RAW, packet->Length, PBUF_REF);
		if (p == NULL) {
			// Drop it
			return 1;
		}
		// memcpy_s(p->payload, p->len, packet->Data, packet->Length);
		p->payload = packet->Data;
		p->len = p->tot_len = packet->Length;
		auto ret = m_interface->input(p, m_interface);
		return ret;
	}
	uint8 Wintun::PushDnsPayload(u32_t addr, uint16 port, const Platform::Array<uint8, 1>^ packet)
	{
		auto p = pbuf_alloc(PBUF_TRANSPORT, packet->Length, PBUF_REF);
		if (p == NULL) {
			return 1;
		}
		// memcpy_s(p->payload, packet->Length, packet->Data, packet->Length);
		p->payload = packet->Data;
		p->len = p->tot_len = packet->Length;
		ip_addr_t ip_dest = { addr };
		auto ret = udp_sendto_if_src(m_dnsPCB, p, &ip_dest, port, m_interface, &m_dns);
		pbuf_free(p);
		return ret;
	}
}

extern "C" {
	void handle_assert_error(char * message, int result) {
		std::string s(message);
		std::wstring ws(s.begin(), s.end());
		throw ref new Platform::FailureException(ref new Platform::String(ws.c_str()) + result.ToString());
	}
}
