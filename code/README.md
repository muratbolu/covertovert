# Covert Storage Channel that exploits Protocol Field Manipulation using TC Flag field in DNS

Group Number: 82

Repository Link: https://github.com/muratbolu/covertovert/tree/PA2

Members:
 * Murat Bolu (2521300)
 * Reza Gholizadeh (2490258)

In this assignment, we implemented protocol field manipulation using TC flag
field in DNS to implement a covert channel. The TC flag field does not contain
the actual bits transmitted, instead, the sender and receiver agree on a
predetermined deterministic finite automaton. The DFA has two states, 0 and 1,
and its alphabet has two symbols, 0 and 1. The symbols are set such that one of
them always causes the state to stay the same, and the other causes the state to
change. The symbol that causes the state to change is called `change_char` and
both parties agree beforehand on the `change_char`. Both parties also agree on
the starting state. In our default config, the starting state is 0 and the
changing character is 1. Therefore, with two parameters, `init_state` and
`change_char`, the DFA is fully described and the parties can communicate with
each other. The sender sends the appropriate character to the receiver and the
receiver always interprets the symbol of the current state as the character
received. With this agreement, the sender does not send the character to the
receiver directly, it tells the receiver to change its state or not. This makes
the message harder to decrypt for third-parties.

In terms of performance, 9 bits per second is achieved. When we time the sending
of 128 bits with terminal commands, it is transmitted in 14 seconds:

```
root@sender:/app# time make send
Sender is running!
/usr/local/lib/python3.10/dist-packages/scapy/sendrecv.py:479: SyntaxWarning: 'iface' has no effect on L3 I/O send(). For multicast/link-local see https://scapy.readthedocs.io/en/latest/usage.html#multicast
  warnings.warn(
Sender is finished!

real    0m14.670s
user    0m4.008s
sys     0m0.305s
```

The warning is caused by the provided `CovertChannelBase.py` and does not affect
functionality.
