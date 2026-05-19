"""Module 4: quantum-assisted entropy (Qiskit simulation with fallback)."""

from __future__ import annotations

import os
from typing import List

_QISKIT_AVAILABLE = False
try:
    from qiskit import QuantumCircuit
    from qiskit_aer import AerSimulator

    _QISKIT_AVAILABLE = True
except ImportError:
    pass


def measure_superposition(num_bits: int) -> List[int]:
    """
    |psi> = (|0> + |1>) / sqrt(2); measure num_bits qubits.
  Returns list of 0/1 bits.
    """
    if num_bits <= 0:
        return []

    if _QISKIT_AVAILABLE:
        simulator = AerSimulator()
        bits: List[int] = []
        batch = min(32, num_bits)
        while len(bits) < num_bits:
            n = min(batch, num_bits - len(bits))
            qc = QuantumCircuit(n, n)
            qc.h(range(n))
            qc.measure(range(n), range(n))
            job = simulator.run(qc, shots=1, memory=True)
            result = job.result()
            memory = result.get_memory()[0]
            bits.extend(int(b) for b in memory[::-1])
        return bits[:num_bits]

    raw = os.urandom((num_bits + 7) // 8)
    return [(raw[i // 8] >> (i % 8)) & 1 for i in range(num_bits)]


def quantum_seed_byte_length(length: int) -> bytes:
    bits = measure_superposition(length * 8)
    out = bytearray(length)
    for i in range(length):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i * 8 + j]
        out[i] = byte
    return bytes(out)


def quantum_simulator_available() -> bool:
    return _QISKIT_AVAILABLE


def quantum_initial_value() -> float:
    bits = measure_superposition(16)
    value = sum(b << i for i, b in enumerate(bits))
    return (value + 1) / 65537.0
