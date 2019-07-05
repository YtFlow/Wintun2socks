#pragma once
// https://stackoverflow.com/questions/10520335/how-to-wrap-a-char-buffer-in-a-winrt-ibuffer-in-c

#include <wrl.h>
#include <wrl/implements.h>
#include <windows.storage.streams.h>
#include <robuffer.h>
#include <vector>

namespace Wintun2socks {
	class NativeBuffer :
		public Microsoft::WRL::RuntimeClass<Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::WinRtClassicComMix>,
		ABI::Windows::Storage::Streams::IBuffer,
		Windows::Storage::Streams::IBufferByteAccess>
	{
	public:
		static Windows::Storage::Streams::IBuffer ^CreateNativeBuffer(LPVOID lpBuffer, DWORD nNumberOfBytes)
		{
			Microsoft::WRL::ComPtr<NativeBuffer> nativeBuffer;
			Microsoft::WRL::Details::MakeAndInitialize<NativeBuffer>(&nativeBuffer, (byte *)lpBuffer, nNumberOfBytes);
			auto iinspectable = (IInspectable *)reinterpret_cast<IInspectable *>(nativeBuffer.Get());
			Windows::Storage::Streams::IBuffer ^buffer = reinterpret_cast<Windows::Storage::Streams::IBuffer ^>(iinspectable);

			return buffer;
		}
		virtual ~NativeBuffer()
		{
			free(m_buffer);
		}

		STDMETHODIMP RuntimeClassInitialize(byte *buffer, UINT totalSize)
		{
			m_length = totalSize;
			m_buffer = buffer;

			return S_OK;
		}

		STDMETHODIMP Buffer(byte **value)
		{
			*value = m_buffer;

			return S_OK;
		}

		STDMETHODIMP get_Capacity(UINT32 *value)
		{
			*value = m_length;

			return S_OK;
		}

		STDMETHODIMP get_Length(UINT32 *value)
		{
			*value = m_length;

			return S_OK;
		}

		STDMETHODIMP put_Length(UINT32 value)
		{
			m_length = value;

			return S_OK;
		}

	private:
		UINT32 m_length;
		byte *m_buffer;
	};
}
