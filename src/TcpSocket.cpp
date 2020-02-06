#include "pch.h"
#include "TcpSocket.h"
#include <exception>

namespace PC = Platform::Collections;

namespace Wintun2socks {
	std::unordered_map<u16_t, TcpSocket^> TcpSocket::m_socketmap;

	err_t TcpSocket::tcp_recv_func(void* arg, tcp_pcb* tpcb, pbuf* p, err_t err) {
		TcpSocket^ socket = nullptr;
		Platform::Array<uint8, 1>^ arr = nullptr;
		auto it = TcpSocket::m_socketmap.find(tpcb->remote_port);
		if (it == TcpSocket::m_socketmap.end()) {
			goto ERR_ABORT;
		}
		socket = it->second;
		if (socket == nullptr) {
			goto ERR_ABORT;
		}
		if (p == NULL) {
			socket->RecvFinished(socket);
			return ERR_OK;
		}
		// TODO: wrap pbuf with a IBuffer
		arr = ref new Platform::Array<uint8, 1>(p->tot_len);
		pbuf_copy_partial(p, arr->begin(), p->tot_len, 0);
		socket->DataReceived(socket, arr);
		tcp_recved(tpcb, p->tot_len);
		pbuf_free(p);
		return ERR_OK;

	ERR_ABORT:
		if (p != NULL) {
			pbuf_free(p);
		}
		tcp_abort(tpcb);
		return ERR_ABRT;
	}
	err_t TcpSocket::tcp_sent_func(void* arg, tcp_pcb* tpcb, u16_t len) {
		TcpSocket^ socket;
		auto it = TcpSocket::m_socketmap.find(tpcb->remote_port);
		if (it == TcpSocket::m_socketmap.end()) {
			goto ERR_ABORT;
		}
		socket = it->second;
		if (socket == nullptr) {
			goto ERR_ABORT;
		}
		socket->DataSent(socket, len, tcp_sndbuf(tpcb));
		return ERR_OK;
	ERR_ABORT:
		tcp_abort(tpcb);
		return ERR_ABRT;
	}
	err_t TcpSocket::tcpAcceptFn(void* arg, struct tcp_pcb* newpcb, err_t err) {
		TcpSocket^ newSocket = ref new TcpSocket(newpcb);
		TcpSocket::EstablishedTcp(newSocket);

		return ERR_OK;
	}
	err_t TcpSocket::tcp_err_func(void* arg, err_t err) {
		if (arg == NULL) return ERR_OK;
		TcpSocket^ socket;
		auto it = TcpSocket::m_socketmap.find((u16_t)arg);
		if (it == TcpSocket::m_socketmap.end()) {
			return ERR_OK;
		}
		socket = it->second;
		if (socket == nullptr) {
			return ERR_OK;
		}
		socket->m_released = true;
		socket->SocketError(socket, err);
		m_socketmap.erase(it->first);
		return ERR_OK;
	}

	TcpSocket::TcpSocket(tcp_pcb* tpcb)
	{
		m_tcpb = tpcb;
		tcp_recv(tpcb, (tcp_recv_fn)&tcp_recv_func);
		tcp_sent(tpcb, (tcp_sent_fn)&tcp_sent_func);
		tcp_err(tpcb, (tcp_err_fn)&tcp_err_func);
		tcp_arg(tpcb, (void*)tpcb->remote_port);
		tcp_nagle_disable(tpcb);

		RemoteAddr = tpcb->local_ip.addr;
		RemotePort = tpcb->local_port;

		TcpSocket::m_socketmap[tpcb->remote_port] = this;
	}
	void TcpSocket::Deinit() {
		m_socketmap.clear();
	}

	uint8 TcpSocket::Send(uint8* packet, u16_t len, bool more)
	{
		if (m_released) {
			return ERR_RST;
		}
		auto flag = TCP_WRITE_FLAG_COPY;
		if (more) {
			flag |= TCP_WRITE_FLAG_MORE;
		}
		auto ret = tcp_write(m_tcpb, packet, len, flag);
		if (ret == ERR_OK) {
			return tcp_output(m_tcpb);
		}
		else return ret;
	}
	uint8 TcpSocket::Send(const Platform::Array<uint8, 1u>^ packet, u16_t len, bool more) {
		return Send(packet->begin(), len, more);
	}
	uint8 TcpSocket::Send(IntPtrAbi packet, u16_t len, bool more) {
		return Send((uint8*)packet, len, more);
	}
	uint8 TcpSocket::Send(Windows::Storage::Streams::Buffer^ packet, bool more)
	{
		if (m_released) return ERR_RST;
		ComPtr<IBufferByteAccess> bufferByteAccess;
		reinterpret_cast<IInspectable*>(packet)->QueryInterface(IID_PPV_ARGS(&bufferByteAccess));
		byte* data = nullptr;
		bufferByteAccess->Buffer(&data);
		return Send(data, packet->Length, more);
	}

	void TcpSocket::Recved(u16_t len) {
		if (m_released) return;
		tcp_recved(m_tcpb, len);
	}
	uint8 TcpSocket::Output() {
		if (m_released) return ERR_RST;
		auto ret = tcp_output(m_tcpb);
		return ret;
	}
	uint8 TcpSocket::Close()
	{
		if (m_released) return -1;
		m_released = true;
		TcpSocket::m_socketmap.erase(m_tcpb->remote_port);
		tcp_arg(m_tcpb, NULL);
		tcp_recv(m_tcpb, NULL);
		tcp_sent(m_tcpb, NULL);
		tcp_err(m_tcpb, NULL);
		uint8 ret;
		if (m_tcpb->local_port == 0) {
			// Already closed
			// ret = tcp_close(m_tcpb);
			// tcp_abort(m_tcpb);
			ret = ERR_OK;
		}
		else {
			ret = tcp_close(m_tcpb);
		}
		return ret;
	}
	void TcpSocket::Abort()
	{
		if (m_released) return;
		m_released = true;
		TcpSocket::m_socketmap.erase(m_tcpb->remote_port);
		tcp_arg(m_tcpb, NULL);
		tcp_recv(m_tcpb, NULL);
		tcp_sent(m_tcpb, NULL);
		tcp_err(m_tcpb, NULL);
		tcp_abort(m_tcpb);
	}
	TcpSocket::~TcpSocket()
	{
		Abort();
	}
	size_t TcpSocket::ConnectionCount() {
		return m_socketmap.size();
	}
	u16_t TcpSocket::SendBufferSize::get() {
		if (m_released) return 0;
		return tcp_sndbuf(m_tcpb);
	}
}
