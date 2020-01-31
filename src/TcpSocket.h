#pragma once
#include "pch.h"
#include "lwip\init.h"
#include "lwip\tcp.h"
#include "Random.h"
#include <collection.h>
#include <wrl.h>
#include <robuffer.h>
#include <unordered_map>

using namespace Windows::Storage::Streams;
using namespace Microsoft::WRL;

namespace WFM = Windows::Foundation::Metadata;

namespace Wintun2socks {
	ref class TcpSocket;
	public delegate void EstablishedTcpHandler(TcpSocket^ incomingSocket);
	public delegate void DataReceivedHandler(TcpSocket^ sender, const Platform::Array<uint8, 1>^ bytes);
	public delegate void DataSentHandler(TcpSocket^ sender, u16_t length, u16_t sendbuf_len);
	public delegate void RecvFinishedHandler(TcpSocket^ sender);
	public delegate void SocketErrorHandler(TcpSocket^ sender, signed int err);

	public interface class ITcpSocket {
		event DataReceivedHandler^ DataReceived;
		event DataSentHandler^ DataSent;
		event SocketErrorHandler^ SocketError;
		event RecvFinishedHandler^ RecvFinished;
	};
	public ref class TcpSocket sealed : [WFM::DefaultAttribute] ITcpSocket
	{
	private:
		static std::unordered_map<u16_t, TcpSocket^> TcpSocket::m_socketmap;
		static err_t TcpSocket::tcp_recv_func (void* arg, tcp_pcb *tpcb, pbuf *p, err_t err);
		static err_t TcpSocket::tcp_sent_func (void* arg, tcp_pcb *tpcb, u16_t len);
		static err_t TcpSocket::tcp_err_func (void* arg, err_t err);
		TcpSocket(tcp_pcb* pcb);
		tcp_pcb* m_tcpb;
		bool m_released;
		uint8 TcpSocket::Send(uint8* packet, u16_t len, bool more);
	internal:
		static err_t TcpSocket::tcpAcceptFn (void *arg, struct tcp_pcb *newpcb, err_t err);
	public:
		property u32_t TcpSocket::RemoteAddr;
		property u16_t TcpSocket::RemotePort;
		property u16_t TcpSocket::SendBufferSize { u16_t get(); }
		static void Deinit();
		[WFM::DefaultOverload]
		uint8 TcpSocket::Send(const Platform::Array<uint8, 1u>^ packet, u16_t len, bool more);
		uint8 TcpSocket::Send(IntPtrAbi packet, u16_t len, bool more);
		uint8 TcpSocket::Send(Windows::Storage::Streams::Buffer^ packet, bool more);
		void TcpSocket::Recved(u16_t len);
		uint8 TcpSocket::Output();
		uint8 TcpSocket::Close();
		void TcpSocket::Abort();
		virtual event DataReceivedHandler^ DataReceived;
		virtual event DataSentHandler^ DataSent;
		virtual event SocketErrorHandler^ SocketError;
		virtual event RecvFinishedHandler^ RecvFinished;
		static event EstablishedTcpHandler^ EstablishedTcp;
		virtual ~TcpSocket();
		static size_t ConnectionCount();
	};
}
