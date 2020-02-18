#include "Wintun.h"
#include <string>
#include <ppltasks.h>

using namespace concurrency;

namespace Wintun2socks {
	Wintun^ Wintun::m_instance = ref new Wintun();
	netif* Wintun::m_interface = netif_default;
	tcp_pcb* Wintun::m_listenPCB = nullptr;
	const ip4_addr_t m_ip = { 0xC0A80301U };
	const ip4_addr_t m_mask = { 0x00000000U };
	bool Wintun::running = false;

	err_t Wintun::outputPCB(struct netif* netif, struct pbuf* p,
		const ip4_addr_t* ipaddr) {
		if (p == NULL) return ERR_OK;
		auto arr = ref new Platform::Array<byte, 1>(p->tot_len);
		pbuf_copy_partial(p, arr->Data, p->tot_len, 0);
		m_instance->PacketPoped(m_instance, arr);
		return ERR_OK;
	}

	void Wintun::Init() {
		if (running) {
			return;
		}
		running = true;
		if (m_listenPCB == nullptr) {
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
		}
	}

	void Wintun::Deinit() {
		TcpSocket::Deinit();
		// tcp_close(m_listenPCB);
	}

	void Wintun::CheckTimeout()
	{
		sys_check_timeouts();
	}

	Wintun^ Wintun::Instance::get() {
		return Wintun::m_instance;
	}
	uint8 Wintun::PushPacket(const Platform::Array<uint8, 1u>^ packet) {
		// Call site ensures that ip protocol is TCP
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
	uint8 Wintun::PushDnsPayload(u32_t addr, uint16 port, IBuffer^ data)
	{
		// Query the IBufferByteAccess interface.
		ComPtr<IBufferByteAccess> bufferByteAccess;
		HRESULT hresult;
		if (FAILED((hresult = reinterpret_cast<IInspectable*>(data)->QueryInterface(IID_PPV_ARGS(&bufferByteAccess))))) {
			throw Platform::COMException::CreateException(hresult);
		}

		// Retrieve the buffer data.
		byte* ptr = nullptr;
		if (FAILED((hresult = bufferByteAccess->Buffer(&ptr)))) {
			throw Platform::COMException::CreateException(hresult);
		}
		return PushUdpPayload(DNS_ADDRESS, DNS_PORT, addr, port, (IntPtrAbi)ptr, (uint16)data->Length);
	}
	uint8 Wintun::PushUdpPayload(u32_t src_addr, uint16 src_port, u32_t dst_addr, uint16 dst_port, IntPtrAbi packet, uint16 packetLen)
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
}

extern "C" {
	void handle_assert_error(char* message, int result) {
		std::string s(message);
		std::wstring ws(s.begin(), s.end());
		throw ref new Platform::FailureException(ref new Platform::String(ws.c_str()) + result.ToString());
	}
}
