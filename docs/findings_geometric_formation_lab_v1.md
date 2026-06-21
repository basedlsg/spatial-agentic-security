# Finding: Geometric Formation Lab v1

Status: geometry-family comparison. The v2 coding wrapper is kept fixed.

## 1. Plain Answer

The experiment tested seven formation families as geometry layers, not as complete
device-security systems:

```text
lattice
sphere_shell
helix
polytope
obstacle_field
braid
voronoi
```

The main result is:

```text
braid is the strongest pure geometry signal in the modeled attack suite
helix and obstacle_field give the best score once runtime cost is included
voronoi is the main warning case because stolen neighbors leak too much
sphere_shell and polytope look elegant but carry symmetry/neighbor-correlation penalties
lattice remains the fastest baseline but misses richer crossing/topology/forbidden-region attacks
```

This supports continuing geometry work, but only in the right place:

```text
geometry helps as a formation authorization signal
geometry does not replace the v2 local wrapper
```

The clean full run used the requested counts:

```text
formation generation        : 500 per family per agent size
geometry attacks            : 1000 per family per attack
partial compromise leakage  : 1000 per family/access/agent size
mutation rigidity           : 500 per mutation type
ablation                    : 300 per ablation/attack/family
agent sweep                 : 5, 10, 20, 50, 100
```

## 2. Why This Experiment Exists

The earlier results narrowed the role of geometry:

```text
3D as the lock was worse than a random secret under partial compromise
3D as a runtime detector did not beat a plain commitment tripwire
v2 showed formation alone does not protect device effects
```

So this experiment asks a narrower and better question:

```text
Which geometry families give a useful coordination signal without leaking across agents
or becoming too expensive?
```

The experiment is not trying to prove that geometry is the security boundary. It is
trying to compare which movement/final-shape/topology ideas are worth keeping inside
the already-fixed v2 wrapper.

## 3. What Stayed Fixed From v2

The v2 wrapper baseline was frozen before the geometry lab:

```text
tag: realistic-coding-gate-v2
tag target: 4234c0c5f536da38ab55311725e06d532a0d01e7
```

The geometry lab did not change:

```text
ActionEnvelope
policy gate
effect binding
transaction binding
constant visible failure wrapper
sidecar isolation checks
```

The new code lives separately:

```text
src/spatial_swarm/spatial_puzzle/geometry_lab/
src/spatial_swarm/spatial_puzzle/experiments/geometric_formation_lab.py
tests/test_geometric_formation_lab.py
```

The new harness compares formation families by swapping the geometry layer only.

## 4. Formation Families Tested

Each family produces a `FormationSpec`:

```text
family_name
agent_ids
action_hash
nonce
risk_level
grid_size
time_steps
endpoints
paths
role_map
obstacle_map
collision_rules
crossing_rules
final_shape_signature
topology_signature
```

Each agent has an `AgentTrajectory`:

```text
agent_id
role
start_point
endpoint
path[t] = (x, y, z)
timing_window
private_digest
```

Families:

| Family | Intent | Expected strength | Expected risk |
| --- | --- | --- | --- |
| `lattice` | separated lattice points and simple lane movement | fast baseline | misses richer geometry |
| `sphere_shell` | endpoints on a hidden shell | global final shape | symmetry and angle ambiguity |
| `helix` | phase/turn-count paths | timing and path sensitivity | higher runtime than simple lattice |
| `polytope` | rigid endpoint skeleton | final-shape clarity | symmetry/reflection ambiguity |
| `obstacle_field` | hidden forbidden zones and detours | path guessing resistance | generation complexity |
| `braid` | crossing order and movement history | strongest topology signal | runtime cost |
| `voronoi` | private spatial cells | local territory constraints | neighbor-correlation leakage |

## 5. Attack Suite

The common attack suite was run against every family:

```text
endpoint_mutation
path_near_miss
collision_mutation
path_crossing_mutation
forbidden_region_mutation
wrong_final_formation
role_swap
timing_shift
delayed_agent
random_guess
nearest_endpoint_guess
shortest_path_guess
same_endpoint_wrong_path
same_path_wrong_timing
collision_avoiding_guess
symmetry_guess
topology_near_miss
```

Family-specific attacks were also included:

```text
sphere_shell: same_radius_wrong_angle, antipodal_endpoint_swap
helix: phase_shift, same_endpoint_wrong_turn_count
polytope: edge_swap, face_reflection, symmetry_rotation
obstacle_field: shortcut_through_obstacle, boundary_skimming_path
braid: wrong_crossing_order, same_endpoint_wrong_braid, late_crossing_swap
voronoi: neighbor_cell_boundary_guess, cell_centroid_guess, stolen_neighbor_cell_inference
```

The verifier checks the enabled signatures for:

```text
endpoint
path
timing
collision
forbidden_region
path_crossing
final_shape
role_binding
topology
```

## 6. Geometry-value Results

The simple score is:

```text
geometry_value_score =
  attack_block_rate
  - false_block_penalty
  - runtime_cost_penalty
  - leakage_penalty
```

It is not a final security formula. It is a ranking aid that keeps the components
visible.

Full-run results at the 20-agent reference size:

| Family | Attack block | A3 bits lost | Runtime p95 ms | Score | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| `helix` | 0.947 | 1.294 | 20.552 | 0.820 | best score; catches path/timing/topology except forbidden-region attack |
| `obstacle_field` | 0.947 | 1.060 | 22.703 | 0.819 | nearly tied; strong forbidden-region signal |
| `braid` | 1.000 | 0.649 | 41.104 | 0.814 | best pure attack blocking; higher runtime |
| `lattice` | 0.824 | 0.885 | 7.224 | 0.762 | fastest; misses crossing/forbidden/topology |
| `polytope` | 0.850 | 2.063 | 11.352 | 0.728 | useful final shape; symmetry/leak penalty |
| `sphere_shell` | 0.842 | 2.533 | 12.384 | 0.698 | elegant but high symmetry/leak penalty |
| `voronoi` | 0.900 | 6.197 | 20.639 | 0.595 | catches many attacks but leaks too much |

Plain reading:

```text
braid is the cleanest geometry answer if the only question is attack blocking
helix and obstacle_field are better balanced if runtime matters
voronoi should not move forward without a leakage redesign
```

## 7. Partial-compromise Leakage

The key leakage question was:

```text
Does stealing Agent A make Agent B easier to fake?
```

At 20 agents:

| Family | A0 target bits | A2 bits lost | A3 bits lost | A3 residual bits |
| --- | ---: | ---: | ---: | ---: |
| `braid` | 29.907 | 0.295 | 0.649 | 29.258 |
| `lattice` | 26.907 | 0.413 | 0.885 | 26.022 |
| `obstacle_field` | 27.907 | 0.528 | 1.060 | 26.847 |
| `helix` | 28.907 | 0.654 | 1.294 | 27.613 |
| `polytope` | 26.907 | 1.013 | 2.063 | 24.844 |
| `sphere_shell` | 26.907 | 1.241 | 2.533 | 24.374 |
| `voronoi` | 27.907 | 2.895 | 6.197 | 21.710 |

Scaling at 100 agents shows the same shape:

| Family | A2 bits lost | A3 bits lost |
| --- | ---: | ---: |
| `braid` | 0.321 | 0.702 |
| `lattice` | 0.445 | 0.958 |
| `obstacle_field` | 0.577 | 1.147 |
| `helix` | 0.698 | 1.403 |
| `polytope` | 1.087 | 2.234 |
| `sphere_shell` | 1.339 | 2.747 |
| `voronoi` | 3.134 | 6.705 |

Plain reading:

```text
braid has the lowest measured neighbor leakage
voronoi recreates the old correlated-neighbor problem
sphere and polytope leak more than their visual appeal would suggest
```

This is the most important negative result. Voronoi is tempting because private cells
sound safe, but the measured model says neighboring cells reveal too much about the
target cell.

## 8. Rigidity Results

Rigidity mutations:

```text
move one endpoint by 1 voxel
move one endpoint by 2 voxels
shift one path step
shift one timing step
swap two roles
mirror the formation
rotate the final formation
remove one path segment
replace one curve with a shortest path
```

Result:

```text
mutation_survival_rate = 0.00 for every family and every mutation type
```

Examples:

| Family | Mutation | Survival | Main reason |
| --- | --- | ---: | --- |
| `lattice` | shift_one_path_step | 0.00 | `wrong_path` |
| `helix` | replace_curve_with_shortest_path | 0.00 | `wrong_path`; `wrong_topology` |
| `braid` | replace_curve_with_shortest_path | 0.00 | `wrong_path`; `wrong_topology` |
| `voronoi` | move_endpoint_1_voxel | 0.00 | `wrong_endpoint` |

Plain reading:

```text
correct formations pass
small wrong formations break clearly
```

This is a useful sanity check, not a complete security result. The mutations are
structured and modeled; they are not an exhaustive geometry-search attack.

## 9. Symmetry Results

Symmetry tests:

```text
rotate_final_shape
reflect_final_shape
swap_symmetric_roles
permute_equal_distance_endpoints
```

All symmetry attacks had release rate 0.00 because role binding and final-shape binding
were enabled in the full gate.

But the ambiguity count still matters:

| Family | Symmetry ambiguity count at 20 agents |
| --- | ---: |
| `sphere_shell` | 72 |
| `polytope` | 48 |
| `voronoi` | 28 |
| `helix` | 20 |
| `braid` | 16 |
| `obstacle_field` | 12 |
| `lattice` | 8 |

Plain reading:

```text
role binding saves symmetric shapes in this model
without role binding, sphere_shell and polytope would be much riskier
```

The lesson is not "never use symmetric shapes." The lesson is:

```text
high symmetry must be broken by role binding or private path/topology
```

## 10. Topology/braid Results

Braid-specific topology tests:

| Test | Attempts | Release | Main reason |
| --- | ---: | ---: | --- |
| `same_endpoint_different_route` | 500 | 0.00 | `wrong_path`; `wrong_topology` |
| `same_route_different_crossing_order` | 500 | 0.00 | `wrong_path_crossing`; `wrong_topology` |
| `same_crossing_order_wrong_timing` | 500 | 0.00 | `wrong_timing` |
| `same_final_shape_wrong_topology` | 500 | 0.00 | `wrong_topology` |

Braid also blocked every full attack-suite class:

```text
attack_block_rate = 1.000
```

The ablation confirms topology matters:

| Braid variant | Attack release | Block rate |
| --- | ---: | ---: |
| `full_geometry` | 0.00 | 1.00 |
| `current_full_gate` | 0.10 | 0.90 |
| `no_topology` | 0.10 | 0.90 |

Plain reading:

```text
braid adds value because it binds movement history, not only final endpoints
same final shape is not enough
same endpoint is not enough
crossing order and topology catch the deeper near misses
```

The tradeoff is cost:

```text
braid runtime p95 at 20 agents: 41.104 ms
braid runtime p95 at 100 agents: 191.747 ms
```

## 11. Runtime And Scaling

Runtime p95 by agent count:

| Family | 5 agents | 20 agents | 100 agents |
| --- | ---: | ---: | ---: |
| `lattice` | 1.806 | 7.224 | 36.119 |
| `sphere_shell` | 3.096 | 12.384 | 61.918 |
| `polytope` | 2.838 | 11.352 | 56.758 |
| `helix` | 5.807 | 20.552 | 95.873 |
| `voronoi` | 5.160 | 20.639 | 103.197 |
| `obstacle_field` | 5.676 | 22.703 | 113.517 |
| `braid` | 11.614 | 41.104 | 191.747 |

Generation failure rates at 100 agents:

| Family | Generation failure | False block |
| --- | ---: | ---: |
| `lattice` | 0.000 | 0.000 |
| `sphere_shell` | 0.002 | 0.000 |
| `helix` | 0.004 | 0.000 |
| `polytope` | 0.012 | 0.000 |
| `obstacle_field` | 0.016 | 0.000 |
| `braid` | 0.060 | 0.000 |
| `voronoi` | 0.046 | 0.000 |

Plain reading:

```text
lattice scales best
braid is most expensive and has the highest generation failure rate at 100 agents
voronoi is also expensive and leakier, so its cost is not buying enough
```

## 12. Best Family

There are two honest answers.

Best by simple value score:

```text
helix
```

Reason:

```text
high attack block rate
moderate leakage
moderate runtime
low generation failure
```

Best by pure geometry strength:

```text
braid
```

Reason:

```text
blocked 100% of modeled attacks
lowest A2/A3 leakage
topology catches same-endpoint and same-final-shape near misses
```

The decision depends on the product goal:

```text
if runtime budget is tight, helix or obstacle_field is better
if the research goal is deepest geometry, braid is the most important
```

## 13. Worst Family

Worst by this run:

```text
voronoi
```

Reason:

```text
A3 bits lost at 20 agents: 6.197
A3 bits lost at 100 agents: 6.705
score: 0.595, lowest of all families
```

Voronoi still blocked 90% of the modeled attack suite, so it is not useless. The problem
is that it reintroduces the older partial-compromise failure mode:

```text
neighbor structure helps infer the target
```

That makes Voronoi risky unless the cell construction is redesigned to reduce
neighbor-correlation leakage.

## 14. What This Supports

This supports the following scoped claim:

```text
In the Geometric Formation Lab v1 model, richer path-history geometry improved the
formation authorization signal compared with endpoint/final-shape-only geometry.
Braid was strongest against the full modeled attack suite, while helix and
obstacle_field were the best runtime-adjusted choices. Voronoi showed significant
partial-compromise leakage and should not be advanced without redesign.
```

It also supports these design lessons:

```text
final shape alone is not enough
endpoint correctness alone is not enough
role binding is mandatory for symmetric shapes
topology matters when attackers can preserve endpoints but alter movement history
forbidden regions help path-guessing resistance
neighbor-correlated geometry must be measured, not assumed safe
```

## 15. What This Does Not Prove

This is not a production security proof.

It does not prove:

| Not proved | Reason |
| --- | --- |
| real-world physical geometry safety | the formations are modeled signatures, not robots or sensors |
| OS/device safety | v2 wrapper remains the device boundary |
| all possible geometric attacks | the suite is broad but finite |
| all topology attacks | braid topology is modeled with signatures and crossing rules |
| true leakage entropy | leakage is a measured model quantity, not a theorem over all formations |
| production runtime | runtime is harness-estimated verifier cost, not deployed distributed latency |
| secure Voronoi is impossible | only this modeled Voronoi family leaked too much |
| secure sphere/polytope is impossible | role binding blocked attacks, but ambiguity remained high |

The zero release rates are observations under this model and these trials, not
impossibility claims.

## 16. Bottom Line

The next geometry direction should be:

```text
braid / crossing-order / path-history geometry
```

The next practical direction should be:

```text
helix or obstacle_field, because they keep most of the attack-blocking value at lower cost
```

The direction to pause:

```text
voronoi, until neighbor leakage is redesigned
```

The project should not go back to "prettier shapes." The useful geometry is movement
history:

```text
who moved where
when they arrived
which route they took
which crossings happened in what order
which private regions they avoided
```

That is the geometric heart that survived this run.

## Run Record

Clean full artifact:

```text
run_dir            : runs/2026-06-21T07-27-43.852644Z
code commit        : 9c1323f3017ddfe050d4e7a62dc69f215652a264
worktree_dirty     : false
metrics sha256     : 7b1d6d757f5b9d05219bdf489b37f912e81369f296827e0ae0786112bf90885a
redaction clean    : true
secret markers     : 0
max RSS            : 149.515625 MB
user CPU seconds   : 153.772845
system CPU seconds : 1.487899
```

Command:

```bash
uv run --extra solvers python -m spatial_swarm.spatial_puzzle.experiments.geometric_formation_lab \
  --families lattice,sphere_shell,helix,polytope,obstacle_field,braid,voronoi \
  --agents 5,10,20,50,100 \
  --trials 500 \
  --attack-trials 1000 \
  --partial-compromise-trials 1000 \
  --mutation-trials 500 \
  --ablation-trials 300
```

Output files:

```text
metrics.json
metrics.json.sha256
geometry_family_summary.csv
attack_matrix.csv
partial_compromise_leakage.csv
rigidity_mutation_results.csv
ablation_results.csv
baseline_results.csv
runtime_scaling.csv
symmetry_results.csv
topology_results.csv
formation_examples/
redaction.json
```

Test run after implementation:

```text
uv run --extra dev --extra solvers pytest
295 passed in 122.78s
```
