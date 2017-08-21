#include "Wintun.h"
#include <string>

namespace Wintun2socks {
	Wintun^ Wintun::m_instance = ref new Wintun();
	netif* Wintun::m_interface = netif_default;
	tcp_pcb* Wintun::m_listenPCB;
	err_t(__stdcall Wintun::outputPCB) (struct netif *netif, struct pbuf *p,
		const ip4_addr_t *ipaddr) {
		auto arr = ref new Platform::Array<uint8, 1u>(p->tot_len);
		pbuf_copy_partial(p, arr->begin(), p->tot_len, 0);
		m_instance->PacketPoped(m_instance, arr);
		return ERR_OK;
	}

	void Wintun::Init() {
		lwip_init();

		// add a listening pcb

		auto pcb = tcp_new();
		auto addr = ip_addr_any;
		tcp_bind(pcb, &addr, 0);
		pcb = tcp_listen_with_backlog(pcb, (UINT)TCP_DEFAULT_LISTEN_BACKLOG);
		Wintun::m_listenPCB = pcb;
		tcp_accept(pcb, (tcp_accept_fn)&TcpSocket::tcpAcceptFn);
		m_interface = netif_list;
		m_interface->mtu = 1500;
		m_interface->output = (netif_output_fn)&Wintun::outputPCB;
	}

	Wintun^ Wintun::Instance::get() {
		return Wintun::m_instance;
	}
	uint8 Wintun::PushPacket(const Platform::Array<uint8, 1u>^ packet) {
		pbuf* p = pbuf_alloc(PBUF_RAW, 0, PBUF_RAM);
		if (p == NULL) {
			// Drop it
			return 1;
		}
		p->payload = packet->Data;
		p->len = p->tot_len = packet->Length;
		auto iphdr = (const struct ip_hdr *)p->payload;
		auto proto = iphdr->_proto;
		if (proto == IP_PROTO_TCP)
			m_interface->input(p, m_interface);
		return 0;
	}
}
