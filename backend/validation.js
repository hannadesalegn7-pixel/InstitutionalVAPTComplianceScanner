const net = require("net");

// Approved lab subnets (you decide the scope)
const ALLOWED_SUBNETS = ["192.168.1.0/24", "127.0.0.1/32"];


function ipToInt(ip) {
  return ip.split(".").reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
}

function inSubnet(ip, cidr) {
  const [base, bits] = cidr.split("/");
  const mask = bits === "0" ? 0 : (~0 << (32 - Number(bits))) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(base) & mask);
}

function validateTarget(target) {
  if (typeof target !== "string" || !net.isIPv4(target.trim())) {
    return {
      ok: false,
      status: 400,
      code: "INVALID_TARGET",
      message: "The submitted target is invalid.",
    };
  }

  const ip = target.trim();

  if (!ALLOWED_SUBNETS.some((subnet) => inSubnet(ip, subnet))) {
    return {
      ok: false,
      status: 403,
      code: "TARGET_NOT_ALLOWED",
      message: "The target is outside the approved scope.",
    };
  }

  return { ok: true, target: ip };
}

module.exports = { validateTarget };
