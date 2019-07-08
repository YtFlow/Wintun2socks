#include "Wintun.h"
#include <string>
#include <ppltasks.h>

using namespace concurrency;

namespace Wintun2socks {
	Wintun^ Wintun::m_instance = ref new Wintun();
	netif* Wintun::m_interface = netif_default;
	tcp_pcb* Wintun::m_listenPCB;
	udp_pcb* Wintun::m_dnsPCB;
	bool Wintun::running = false;
	err_t(__stdcall Wintun::outputPCB) (struct netif *netif, struct pbuf *p,
		const ip4_addr_t *ipaddr) {
		if (p == NULL) return ERR_OK;
		// u8_t *data = (u8_t *)malloc(p->tot_len);
		auto arr = ref new Platform::Array<byte, 1>(p->tot_len);
		pbuf_copy_partial(p, arr->Data, p->tot_len, 0);
		m_instance->PacketPoped(m_instance, arr);
		// IBuffer ^buf = NativeBuffer::CreateNativeBuffer(data, p->tot_len);
		// try {
		// 	m_outputSocket->OutputStream->WriteAsync(buf);
		// }
		// catch (Platform::Exception^) {
		// 	;
		// }
		return ERR_OK;
	}

	err_t(Wintun::recvUdp)(void * arg, udp_pcb * pcb, pbuf * p, const ip_addr_t * addr, u16_t port)
	{
		auto arr = ref new Platform::Array<uint8, 1u>(p->tot_len);
		pbuf_copy_partial(p, arr->begin(), p->tot_len, 0);
		m_instance->DnsPacketPoped(m_instance, arr, addr->addr, port);
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
		m_interface = netif_list;
		m_interface->mtu = 1500;
		m_interface->output = (netif_output_fn)&Wintun::outputPCB;

		// UDP pcb for DNS
		m_dnsPCB = udp_new();
		ip_addr_t dns_ip;
		dns_ip.addr = 0x01010101;
		udp_bind(m_dnsPCB, &dns_ip, 53);
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
		pbuf* p = pbuf_alloc(PBUF_RAW, packet->Length, PBUF_RAM);
		if (p == NULL) {
			// Drop it
			return 1;
		}
		memcpy_s(p->payload, p->len, packet->Data, packet->Length);
		auto ret = m_interface->input(p, m_interface);
		return ret;
	}
	uint8 Wintun::PushDnsPayload(u32_t addr, uint16 port, const Platform::Array<uint8, 1>^ packet)
	{
		auto p = pbuf_alloc(PBUF_TRANSPORT, packet->Length, PBUF_RAM);
		memcpy_s(p->payload, packet->Length, packet->Data, packet->Length);
		ip_addr_t ip_dest = { addr };
		ip_addr_t ip_src = { 0x01010101 };
		auto ret = udp_sendto_if_src(m_dnsPCB, p, &ip_dest, port, m_interface, &ip_src);
		return ret;
	}
}
