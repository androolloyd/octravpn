"""The real separate target kernel, with bounded observation of client TCP MSS."""
import json
import pathlib
import struct
import packet_target


class ObservedHop(packet_target.Hop):
    def __init__(self, *args, **kwargs):
        self.mss = []
        super().__init__(*args, **kwargs)

    def _valid(self, data, *, outgoing):
        valid = super()._valid(data, outgoing=outgoing)
        if valid and not outgoing and data[9] == 6:
            offset = (data[0] & 15) * 4
            # Client SYN only; the target's SYNACK advertises its own MTU.
            if len(data) >= offset + 20 and data[offset + 13] & 0x12 == 0x02:
                options = data[offset + 20:offset + (data[offset + 12] >> 4) * 4]
                index = 0
                while index < len(options):
                    kind = options[index]
                    if kind == 0: break
                    if kind == 1: index += 1; continue
                    if index + 1 >= len(options): break
                    length = options[index + 1]
                    if length < 2 or index + length > len(options): break
                    if kind == 2 and length == 4:
                        self.mss.append(struct.unpack_from('!H', options, index + 2)[0])
                        self.mss = self.mss[-32:]
                        path = pathlib.Path('/evidence/tcp-mss.json')
                        temporary = path.with_suffix('.part'); temporary.write_text(json.dumps(self.mss)); temporary.replace(path)
                    index += length
        return valid


if __name__ == '__main__': raise SystemExit(packet_target.main(hop_factory=ObservedHop))
