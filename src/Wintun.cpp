#include "Wintun.h"
#include <string>
#include <ppltasks.h>

using namespace concurrency;

namespace Wintun2socks {
	Wintun^ Wintun::m_instance = ref new Wintun();
	netif* Wintun::m_interface = netif_default;
	tcp_pcb* Wintun::m_listenPCB;
	udp_pcb* Wintun::m_udpPCB;
	// const ip4_addr_t m_ip = { 0xC0A80301U };
	const ip4_addr_t m_dns = { 0x01010101U };
	const ip4_addr_t m_mask = { 0x00000000U };
	const u16_t m_dnsPort = 53;
	bool Wintun::running = false;
	err_t Wintun::outputPCB(struct netif* netif, struct pbuf* p,
		const ip4_addr_t* ipaddr) {
		if (p == NULL) return ERR_OK;
		auto arr = ref new Platform::Array<byte, 1>(p->tot_len);
		pbuf_copy_partial(p, arr->Data, p->tot_len, 0);
		m_instance->PacketPoped(m_instance, arr);
		return ERR_OK;
	}

	err_t(Wintun::recvUdp)(void* arg, udp_pcb* pcb, pbuf* p, const ip_addr_t* addr, u16_t port)
	{
		auto arr = ref new Platform::Array<uint8, 1u>(p->tot_len);
		pbuf_copy_partial(p, arr->begin(), p->tot_len, 0);
		if (pcb->local_port == 53 && pcb->local_ip.addr == m_dns.addr) {
			m_instance->DnsPacketPoped(m_instance, arr, addr->addr, port);
		}
		else {

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
		m_interface = (struct netif*)malloc(sizeof(struct netif));
		if (m_interface == nullptr) {
			throw ref new Platform::FailureException(L"Cannot initialize a netif");
		}
		netif_add(m_interface, &m_mask, &m_mask, IP_ADDR_ANY, NULL, NULL, &ip_input);
		netif_set_up(m_interface);
		netif_set_link_up(m_interface);
		netif_set_default(m_interface);
		m_interface->mtu = 1500;
		m_interface->output = (netif_output_fn)&Wintun::outputPCB;
		m_interface->input = &ip_input;

		// UDP pcb
		m_udpPCB = udp_new();
		udp_bind(m_udpPCB, &m_dns, m_dnsPort);
		udp_recv(m_udpPCB, (udp_recv_fn)&Wintun::recvUdp, NULL);
	}

	void Wintun::Deinit() {
		TcpSocket::Deinit();
		UdpSocket::Deinit();
		udp_remove(m_udpPCB);
		tcp_abort(m_listenPCB);
	}

	void Wintun::CheckTimeout()
	{
		sys_check_timeouts();
	}

	Wintun^ Wintun::Instance::get() {
		return Wintun::m_instance;
	}
	uint8 Wintun::PushPacket(const Platform::Array<uint8, 1u>^ packet) {
		if (packet->Length < IP_HLEN) {
			return ERR_OK;
		}
		// Check L4 protocol
		ip_hdr* iphdr = (ip_hdr*)(void*)packet->Data;
		if (IPH_V(iphdr) != 4) {
			return 1;
		}
		auto ipProto = IPH_PROTO(iphdr);
		if (ipProto != IP_PROTO_TCP && ipProto != IP_PROTO_UDP) {
			return 1;
		}
		// Peek UDP remote port so that we can bind the port before the packet is sent into the stack
		while (ipProto == IP_PROTO_UDP && packet->Length >= IP_HLEN + UDP_HLEN) {
			auto remoteAddr = iphdr->dest.addr;
			auto udphdr = (udp_hdr*)(void*)(packet->Data + IP_HLEN);
			auto remotePort = lwip_ntohs(udphdr->src);
			if (remoteAddr == m_dns.addr && remotePort == m_dnsPort) {
				// DNS packets are handled separately
				break;
			}
			auto localAddr = iphdr->src.addr;
			UdpSocket::bind(localAddr, lwip_ntohs(udphdr->src), remoteAddr, lwip_ntohs(udphdr->dest));
			break;
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
		auto ret = udp_sendto_if_src(m_udpPCB, p, &ip_dest, port, m_interface, &m_dns);
		pbuf_free(p);
		return ret;
	}
}

extern "C" {
	void handle_assert_error(char* message, int result) {
		std::string s(message);
		std::wstring ws(s.begin(), s.end());
		throw ref new Platform::FailureException(ref new Platform::String(ws.c_str()) + result.ToString());
	}
}
