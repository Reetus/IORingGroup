// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025, ModernUO

using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace System.Network;

/// <summary>
/// Address family numbers and sockaddr layout of one platform's socket API.
/// </summary>
internal readonly struct SocketAddressLayout
{
    /// <summary>IPPROTO_IPV6, the option level for <see cref="Ipv6V6Only"/>; 41 on every supported platform.</summary>
    public const int IPPROTO_IPV6 = 41;

    /// <summary>AF_INET.</summary>
    public readonly int InterNetwork;

    /// <summary>AF_INET6.</summary>
    public readonly int InterNetworkV6;

    /// <summary>IPV6_V6ONLY option name.</summary>
    public readonly int Ipv6V6Only;

    /// <summary>BSD-derived systems prefix sockaddr with a length byte and use a one-byte family.</summary>
    public readonly bool LengthPrefixed;

    private SocketAddressLayout(int interNetwork, int interNetworkV6, int ipv6V6Only, bool lengthPrefixed)
    {
        InterNetwork = interNetwork;
        InterNetworkV6 = interNetworkV6;
        Ipv6V6Only = ipv6V6Only;
        LengthPrefixed = lengthPrefixed;
    }

    public static SocketAddressLayout Windows => new(2, 23, 27, false);

    public static SocketAddressLayout Linux => new(2, 10, 26, false);

    /// <summary>The kqueue backend's platform: macOS uses AF_INET6 30, FreeBSD 28.</summary>
    public static SocketAddressLayout Bsd => OperatingSystem.IsFreeBSD() ? FreeBsd : MacOS;

    public static SocketAddressLayout MacOS => new(2, 30, 27, true);

    public static SocketAddressLayout FreeBsd => new(2, 28, 27, true);
}

/// <summary>
/// A listener's bind address encoded as a native sockaddr.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeSocketAddress
{
    private const int SockaddrInLength = 16;
    private const int SockaddrIn6Length = 28;

    /// <summary>sizeof(sockaddr_in6), the larger of the two.</summary>
    public const int MaxLength = SockaddrIn6Length;

    /// <summary>The sockaddr bytes; pass <c>Data</c> and <see cref="Length"/> to bind.</summary>
    public fixed byte Data[MaxLength];

    /// <summary>Bytes of <see cref="Data"/> in use.</summary>
    public int Length;

    /// <summary>Address family to create the socket with.</summary>
    public int Family;

    /// <summary>Whether this is an IPv6 address, so IPV6_V6ONLY applies.</summary>
    public bool IsIPv6;

    /// <summary>
    /// Parses a bind address. Null or empty means every IPv4 interface.
    /// </summary>
    /// <remarks>
    /// IPv4 must be a canonical dotted quad. Host names and the shorthand forms
    /// <see cref="IPAddress.TryParse(string, out IPAddress)"/> allows ("127.1", "2130706433") are
    /// rejected, so a mistyped address fails instead of binding somewhere unexpected.
    /// IPv6 may be bracketed ("[::1]") and may carry a scope ("fe80::1%3"), but not a port.
    /// </remarks>
    public static bool TryParseBindAddress(string? bindAddress, out IPAddress address)
    {
        if (string.IsNullOrEmpty(bindAddress))
        {
            address = IPAddress.Any;
            return true;
        }

        address = IPAddress.None;

        if (bindAddress.Contains(':'))
        {
            var text = bindAddress.AsSpan();
            if (text.Length > 2 && text[0] == '[' && text[^1] == ']')
            {
                text = text[1..^1];
            }

            // Leftover brackets mean "[::1]:2593" or similar; IPAddress would drop the port.
            if (text.ContainsAny('[', ']') ||
                !IPAddress.TryParse(text, out var v6) ||
                v6.AddressFamily != AddressFamily.InterNetworkV6)
            {
                return false;
            }

            address = v6;
            return true;
        }

        if (!IPAddress.TryParse(bindAddress, out var v4) ||
            v4.AddressFamily != AddressFamily.InterNetwork ||
            v4.ToString() != bindAddress)
        {
            return false;
        }

        address = v4;
        return true;
    }

    /// <summary>
    /// Encodes <paramref name="bindAddress"/> and <paramref name="port"/> for <paramref name="layout"/>.
    /// </summary>
    /// <returns>False when the address is not one <see cref="TryParseBindAddress"/> accepts.</returns>
    public static bool TryCreate(string? bindAddress, ushort port, in SocketAddressLayout layout, out NativeSocketAddress result)
    {
        result = default;
        if (!TryParseBindAddress(bindAddress, out var address))
        {
            return false;
        }

        var bytes = MemoryMarshal.CreateSpan(ref result.Data[0], MaxLength);

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // sockaddr_in6: family(2) port(2) flowinfo(4) addr(16) scope_id(4)
            result.Length = SockaddrIn6Length;
            result.Family = layout.InterNetworkV6;
            result.IsIPv6 = true;
            WriteFamily(bytes, layout, result.Length, result.Family);
            BinaryPrimitives.WriteUInt16BigEndian(bytes[2..], port);
            address.TryWriteBytes(bytes.Slice(8, 16), out _);
            // sin6_scope_id is host order.
            MemoryMarshal.Write(bytes[24..], (uint)address.ScopeId);
            return true;
        }

        // sockaddr_in: family(2) port(2) addr(4) zero(8)
        result.Length = SockaddrInLength;
        result.Family = layout.InterNetwork;
        WriteFamily(bytes, layout, result.Length, result.Family);
        BinaryPrimitives.WriteUInt16BigEndian(bytes[2..], port);
        address.TryWriteBytes(bytes.Slice(4, 4), out _);
        return true;
    }

    private static void WriteFamily(Span<byte> bytes, in SocketAddressLayout layout, int length, int family)
    {
        if (layout.LengthPrefixed)
        {
            // BSD splits the 16-bit family into sin_len and sa_family.
            bytes[0] = (byte)length;
            bytes[1] = (byte)family;
        }
        else
        {
            // sa_family_t is a host-order 16-bit field.
            MemoryMarshal.Write(bytes, (ushort)family);
        }
    }
}
