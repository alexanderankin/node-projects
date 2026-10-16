#!/usr/bin/env node

const net = require("node:net");

function parseCidr(cidr) {
  const [address, prefixString] = cidr.split("/");
  const version = net.isIP(address);
  const prefix = Number(prefixString);

  if (!version)
    throw new Error(`Invalid IP address: ${address}`);

  const bits = version === 4 ? 32 : 128;

  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits)
    throw new Error(`Invalid CIDR prefix: ${prefixString}`);

  if (version === 4)
    return parseIpv4Cidr(address, prefix);

  return parseIpv6Cidr(address, prefix);
}

function parseIpv4Cidr(address, prefix) {
  const ip = address
    .split(".")
    .reduce((n, octet) => (n << 8n) | BigInt(octet), 0n);

  const hostBits = 32n - BigInt(prefix);
  const mask = ((1n << 32n) - 1n) << hostBits & ((1n << 32n) - 1n);

  const first = ip & mask;
  const last = first | ((1n << hostBits) - 1n);

  return {
    version: 4,
    prefix,
    first: bigintToIpv4(first),
    last: bigintToIpv4(last),
  };
}

function bigintToIpv4(value) {
  return [24n, 16n, 8n, 0n]
    .map(shift => Number((value >> shift) & 0xffn))
    .join(".");
}

function parseIpv6Cidr(address, prefix) {
  const ip = ipv6ToBigint(address);

  const hostBits = 128n - BigInt(prefix);
  const mask =
    ((1n << 128n) - 1n) << hostBits &
    ((1n << 128n) - 1n);

  const first = ip & mask;
  const last = first | ((1n << hostBits) - 1n);

  return {
    version: 6,
    prefix,
    first: bigintToIpv6(first),
    last: bigintToIpv6(last),
  };
}

function ipv6ToBigint(address) {
  let [left, right] = address.split("::");

  const leftParts = left ? left.split(":") : [];
  const rightParts = right ? right.split(":") : [];

  // Handle embedded IPv4, e.g. ::ffff:192.168.1.1
  const expandIpv4 = parts => {
    if (!parts.length)
      return parts;

    const last = parts.at(-1);

    if (!last.includes("."))
      return parts;

    const octets = last.split(".").map(Number);

    return [
      ...parts.slice(0, -1),
      ((octets[0] << 8) | octets[1]).toString(16),
      ((octets[2] << 8) | octets[3]).toString(16),
    ];
  };

  const lhs = expandIpv4(leftParts);
  const rhs = expandIpv4(rightParts);

  const missing = 8 - lhs.length - rhs.length;

  const parts = address.includes("::")
    ? [...lhs, ...Array(missing).fill("0"), ...rhs]
    : lhs;

  if (parts.length !== 8)
    throw new Error(`Invalid IPv6 address: ${address}`);

  return parts.reduce(
    (value, part) => (value << 16n) | BigInt(`0x${part || "0"}`),
    0n
  );
}

function bigintToIpv6(value) {
  const parts = [];

  for (let shift = 112n; shift >= 0n; shift -= 16n)
    parts.push(((value >> shift) & 0xffffn).toString(16));

  return parts.join(":");
}

if (require.main === module) {
  console.log([parseCidr(process.argv[2])].map(e => ([e.first, e.last]))[0]);
}

module.exports.getIpRangeFromAddressAndNetmask = parseCidr;
module.exports.parseCidr = parseCidr;
