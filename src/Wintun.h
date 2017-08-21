#pragma once
#include "lwip\init.h"
#include "lwip\tcp.h"
#include "pch.h"
#include "TcpSocket.h"

namespace WFM = Windows::Foundation::Metadata;

namespace Wintun2socks {
	public delegate void PacketPopedHandler(Platform::Object^ sender, const Platform::Array<uint8, 1>^ e);
	ref class Wintun;
	public interface class IWintun {
		event PacketPopedHandler^ PacketPoped;
		void Init();
		uint8 PushPacket(const Platform::Array<uint8, 1u>^ packet);
	};
	public ref class Wintun sealed: [WFM::DefaultAttribute] IWintun
	{
	private:
		static Wintun^ m_instance;
		static netif* m_interface;
		static tcp_pcb* m_listenPCB;
		static err_t(__stdcall Wintun::outputPCB) (struct netif *netif, struct pbuf *p,
			const ip4_addr_t *ipaddr);

	public:
		static property Wintun^ Instance { Wintun^ get(); };
		virtual void Init();
		virtual uint8 PushPacket(const Platform::Array<uint8, 1u>^ packet);
		virtual event PacketPopedHandler^ PacketPoped;
	};
}
