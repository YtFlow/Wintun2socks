#pragma once
#include "lwip\udp.h"
#include <unordered_map>

namespace Wintun2socks {
	ref class UdpSocket;
	public delegate void UdpAssociateHandler(UdpSocket^ sender);
	public delegate void DatagramReceivedHandler(UdpSocket^ sender, const Platform::Array<uint8, 1>^ data, u32_t addr, u16_t port);
	public ref class UdpSocket sealed
	{
	private:
		static std::unordered_map<uint16, UdpSocket^> UdpSocket::m_socketmap;
		udp_pcb* pcb;
		bool m_closed = false;
		UdpSocket(u32_t localAddr, u16_t localPort, udp_pcb* pcb);
		static void udp_recv_func(void* arg, struct udp_pcb* pcb, struct pbuf* p,
			const ip_addr_t* addr, u16_t port);
	internal:
		static err_t bind(u32_t localAddr, u16_t localPort, u32_t remoteAddr, u16_t remotePort);
		static void Deinit();
	public:
		static event UdpAssociateHandler^ OnPortAssociate;
		property u32_t RemoteAddr;
		property u16_t RemotePort;
		u8_t Send(const Platform::Array<uint8, 1>^ data);
		event DatagramReceivedHandler^ OnReceive;
		void Close();
		virtual ~UdpSocket();
	};
}

