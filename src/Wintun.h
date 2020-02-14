#pragma once
#include "lwip\init.h"
#include "lwip\timeouts.h"
#include "lwip\tcp.h"
#include "lwip\udp.h"
#include "pch.h"
#include "TcpSocket.h"
#include "NativeBuffer.h"

namespace WFM = Windows::Foundation::Metadata;

namespace Wintun2socks {
	public delegate void PacketPopedHandler(Platform::Object^ sender, const Platform::Array<uint8, 1>^ e);
	ref class Wintun;
	public interface class IWintun {
		event PacketPopedHandler^ PacketPoped;
		void Init();
		void Deinit();
		void CheckTimeout();
		uint8 PushDnsPayload(u32_t addr, uint16 port, const Platform::Array<uint8, 1>^ data);
		uint8 PushUdpPayload(u32_t src_addr, uint16 src_port, u32_t dst_addr, uint16 dst_port, IntPtrAbi packet, uint16 packetLen);
		uint8 PushPacket(const Platform::Array<uint8, 1u>^ packet);
	};
	public ref class Wintun sealed: [WFM::DefaultAttribute] IWintun
	{
	private:
		static bool running;
		static Wintun^ m_instance;
		static netif* m_interface;
		static tcp_pcb* m_listenPCB;
		static err_t Wintun::outputPCB (struct netif *netif, struct pbuf *p,
			const ip4_addr_t *ipaddr);
        const uint32 DNS_ADDRESS = 0x01010101U;
        const uint16 DNS_PORT = 53;

	public:
		static property Wintun^ Instance { Wintun^ get(); };
		virtual void Init();
		virtual void Deinit();
		virtual void CheckTimeout();
		virtual uint8 PushPacket(const Platform::Array<uint8, 1u>^ packet);
		virtual uint8 PushDnsPayload(u32_t addr, uint16 port, const Platform::Array<uint8, 1>^ data);
		virtual uint8 PushUdpPayload(u32_t src_addr, uint16 src_port, u32_t dst_addr, uint16 dst_port, IntPtrAbi packet, uint16 packetLen);
		virtual event PacketPopedHandler^ PacketPoped;
	};
}
