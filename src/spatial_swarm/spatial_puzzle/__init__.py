"""Sealed adversarial spatial-puzzle research system.

Builds the strongest hidden-constraint 3D polycube puzzle (private connector
labels, hidden topology, decoy fits, internal cavities) and tests whether it adds
attacker cost under partial compromise and one-shot failure, vs a random secret at
matched entropy. UCOG (the cryptographic gate) is frozen and untouched; this
package reuses the spatial_lab primitives. The random-secret baseline is the
residual-entropy ceiling; the build is engineered so an honest negative result is
fully supported.
"""
