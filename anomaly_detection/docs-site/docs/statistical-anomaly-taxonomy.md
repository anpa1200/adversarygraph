# Statistical Anomaly Taxonomy

This document lists statistically relevant anomaly types without tying them to any specific application domain. An anomaly is an observation, group of observations, relationship, sequence, or distributional state that deviates meaningfully from an appropriate reference model.

No single taxonomy is mutually exclusive. The same observation may simultaneously be, for example, a contextual, multivariate, local, and temporal anomaly. The categories below describe different statistical properties of anomalous data.

The overall taxonomy is grounded in established statistical-outlier and anomaly-detection literature, particularly the broad taxonomies and methodological treatments in Chandola et al. [1], Aggarwal [2], Barnett and Lewis [3], Hodge and Austin [4], and Pang et al. [5].

## Fundamental Observation-Level Anomalies

Academic grounding: [1-4, 6-8].

### 1. Global Point Anomaly

A single observation is unusually distant from the overall data distribution. Its anomalousness does not depend on a local neighborhood, time, subgroup, or external context. A value may be considered globally anomalous when it lies in a low-density region or far beyond the central tendency and dispersion of the full population.

This type assumes that comparing the observation with the entire reference population is meaningful. It can be misleading when the population contains distinct subgroups or when the distribution changes over time.

### 2. Local Point Anomaly

A single observation is unusual relative to nearby or otherwise similar observations, even if it is not unusual relative to the complete population. Local anomalies occur in heterogeneous data where different regions have different densities, scales, or expected behaviors.

The definition of neighborhood is essential. It may be based on geometric distance, feature similarity, group membership, or a learned manifold. An observation can appear normal globally while being highly improbable within its local neighborhood.

### 3. Contextual Anomaly

An observation is anomalous only under a particular context. The same value may be normal in one context and abnormal in another. Context can include time, location, category, experimental condition, season, population segment, or any conditioning variable.

A contextual anomaly requires two classes of attributes: contextual attributes that define the relevant comparison set, and behavioral attributes whose values are evaluated within that context.

### 4. Collective Anomaly

A group of observations is anomalous as a collection even though each individual observation may appear normal. The anomaly exists in the group's combined structure, frequency, ordering, shape, or relationship.

Collective anomalies require a meaningful way to define groups or windows. They commonly occur in sequences, time series, spatial regions, repeated measurements, and transaction sets.

### 5. Conditional Anomaly

An observation is anomalous because its value is improbable given the values of other variables. The observed value itself may be common, but the conditional combination is rare.

Formally, the anomaly is associated with a low conditional probability, such as a low value of `P(Y | X)`. Conditional anomalies are central to regression diagnostics, probabilistic graphical models, and context-aware analysis.

### 6. Residual Anomaly

An observation is anomalous because the difference between its observed value and a model's predicted value is unusually large. The residual may be evaluated in absolute terms, relative to expected variance, or against a modeled residual distribution.

Residual anomalies depend on model adequacy. A large residual can indicate an unusual observation, but it can also expose a misspecified model, omitted variable, incorrect functional form, or structural change.

## Baseline-Relative Anomalies

Academic grounding: [1, 2, 6, 7, 9].

### 7. Self-Baseline Anomaly

An entity or process deviates from its own historical distribution. The reference model is specific to the same entity rather than the complete population.

This approach is useful when entities have stable but substantially different normal behaviors. It requires sufficient historical observations and becomes unreliable during cold-start periods or after legitimate permanent change.

### 8. Peer-Group Anomaly

An entity deviates from a population of statistically comparable entities. Peers may be defined by known categories or discovered through clustering, similarity, latent representations, or matched covariates.

Peer-group anomalies are especially useful when an entity has little history. Their quality depends on whether the selected peers are genuinely comparable and whether the peer group itself is sufficiently homogeneous.

### 9. Population Anomaly

An observation or entity deviates from the distribution of the full reference population. Unlike a peer-group anomaly, the comparison is not limited to a selected subgroup.

Population anomalies provide broad coverage but can obscure meaningful subgroup differences. They are most reliable when the population is reasonably homogeneous or when subgroup effects have already been normalized.

### 10. Cohort Anomaly

A complete cohort or subgroup behaves differently from other comparable cohorts. The anomalous unit is the group rather than an individual member.

Cohort anomalies can appear as shifts in means, variances, proportions, correlations, or outcome distributions. They require controls for cohort size, composition, and confounding variables.

### 11. Reference-Profile Anomaly

An observation differs from a predefined or learned canonical profile. The profile may represent a prototype, centroid, expected curve, template, or normative distribution.

Unlike a self-baseline, the reference profile may be external or shared. The anomaly score reflects distance from that profile and depends strongly on how the profile and distance function are defined.

## Magnitude, Frequency, and Rate Anomalies

Academic grounding: [2, 3, 10, 11].

### 12. Magnitude Anomaly

A measured value is unusually large or small relative to its expected distribution. Magnitude anomalies concern the level of a variable rather than its frequency, ordering, or relationships.

They may be one-sided or two-sided and should account for skewness, heavy tails, transformations, and context-dependent variance.

### 13. Count Anomaly

The number of events or occurrences in a defined interval or group is unusual. Count anomalies are evaluated using count distributions or empirical count baselines.

The expected variance matters. Poisson assumptions are often too restrictive when data are overdispersed, underdispersed, zero-inflated, or affected by seasonality.

### 14. Rate Anomaly

The number of events per unit of exposure is unusual. Exposure may be time, population size, area, number of opportunities, or another denominator.

Rate anomalies differ from count anomalies because a high count may be normal under high exposure. Reliable analysis requires a correct and stable denominator.

### 15. Volume Anomaly

The aggregate quantity accumulated over a window is unusual. Volume may combine many individual measurements and may represent a sum, total mass, total size, or total amount.

Volume anomalies may result from more events, larger events, or both. Decomposing these components is often necessary to explain the anomaly.

### 16. Burst Anomaly

Events occur in an unusually concentrated cluster over a short interval. A burst is defined by a temporary increase in local event intensity rather than merely a high total count over a long period.

Burst analysis should compare short-term intensity with both the normal background rate and expected burstiness of the process.

### 17. Drought or Silence Anomaly

Expected observations or events fail to occur for an unusually long period. This is a negative anomaly based on absence rather than an observed extreme value.

Detection requires an expectation that observations should occur. Irregular sampling, outages, censoring, and missing data must be distinguished from genuine absence.

### 18. Duration Anomaly

An event, state, or interval persists for an unusually short or long duration. The anomaly concerns elapsed time rather than event count or magnitude.

Duration distributions are often skewed or censored, so survival-analysis methods may be more appropriate than symmetric deviation measures.

### 19. Inter-Arrival-Time Anomaly

The time between consecutive events is unusual. Anomalies may be unexpectedly short gaps, unexpectedly long gaps, or a changed distribution of gaps.

Inter-arrival analysis helps distinguish changes in event timing that aggregate counts can hide. It requires careful handling of nonstationary event rates.

### 20. Ratio or Proportion Anomaly

A ratio, share, composition percentage, or success fraction deviates from its expected range. The total volume may remain normal while the relative composition changes.

Ratios become unstable with small denominators. Statistical evaluation should account for denominator size and the bounded nature of proportions.

## Time-Series and Temporal Anomalies

Academic grounding: [12-16].

### 21. Temporal-Context Anomaly

An observation is unusual for its specific temporal context, such as time of day, day of week, season, phase, or position within a cycle. The same value may be normal at another time.

The model must represent relevant periodic patterns and calendars. Otherwise, regular seasonality can be incorrectly flagged as anomalous.

### 22. Trend Anomaly

The direction or slope of a series changes unexpectedly. This may be a sudden reversal, unusual acceleration, unusual deceleration, or a trend inconsistent with its historical behavior.

Trend anomalies differ from point anomalies because individual values may remain within normal ranges while their sustained direction is unusual.

### 23. Level-Shift Anomaly

The mean or typical level of a process changes abruptly and remains at the new level. A level shift is a persistent structural change rather than a temporary spike.

The key challenge is distinguishing a genuine regime change from a long-lived but temporary disturbance.

### 24. Variance-Shift Anomaly

The variability of a process changes materially while its mean may remain stable. The process may become unexpectedly volatile or unexpectedly uniform.

Variance shifts can be more informative than level shifts when instability itself is the abnormal condition. Robust methods are needed because extreme points can falsely suggest increased variance.

### 25. Change-Point Anomaly

A statistically significant boundary separates two segments generated by different processes or parameter values. The changed property may be mean, variance, trend, frequency, correlation, or the full distribution.

Change-point analysis identifies when a structural transition occurred. It does not automatically determine whether the new regime is undesirable or anomalous in a substantive sense.

### 26. Seasonal Anomaly

An observation or pattern deviates from the expected seasonal component of a series. It may occur at an unusual phase, have an unusual seasonal magnitude, or violate a recurring cycle.

Seasonal anomalies require enough history to estimate cycles and must accommodate changing seasonal strength or multiple overlapping periods.

### 27. Periodicity Anomaly

The presence, absence, frequency, or strength of a repeating pattern is unusual. A process may acquire a new periodic cycle, lose an established cycle, or shift its dominant frequency.

Periodicity anomalies are often examined using spectral density and autocorrelation in the frequency domain, or wavelet representations in the time-frequency domain.

### 28. Phase Anomaly

A periodic process remains similar in shape and frequency but occurs earlier or later than expected. The anomaly is a displacement in phase rather than magnitude.

Phase anomalies can be hidden by aggregate statistics and require alignment against an expected cycle or template.

### 29. Shape Anomaly

A segment of a curve or time series has an unusual shape even when its level, duration, and total volume are normal. Shape concerns the internal trajectory, such as rise-and-fall form, curvature, or waveform.

Shape anomalies commonly require subsequence comparison, functional-data analysis, dynamic time warping, or learned representations.

### 30. Subsequence Anomaly

A contiguous segment of a sequence or time series is unusual relative to other segments. The anomaly may involve its values, shape, transitions, or internal temporal structure.

The choice of subsequence length strongly influences results. Variable-length methods are needed when anomalous patterns do not have a known duration.

### 31. Forecast Anomaly

An observed future value or interval falls outside the predictive distribution generated from prior observations. Unlike a general residual anomaly, a forecast anomaly explicitly concerns out-of-sample temporal prediction.

Prediction intervals should account for horizon-dependent uncertainty, seasonality, parameter uncertainty, and changing variance.

### 32. Autocorrelation Anomaly

The dependence between observations at one or more time lags changes unexpectedly. Values may individually appear normal while their temporal dependence becomes unusual.

This anomaly can indicate that a process has become more persistent, more alternating, or differently cyclical without a clear shift in mean or variance.

### 33. Synchronization Anomaly

Multiple series become unusually synchronized, desynchronized, or phase-locked. The anomaly lies in their temporal coordination rather than in any single series.

Synchronization analysis must account for shared seasonality and common external drivers that can create expected co-movement.

## Distributional Anomalies

Academic grounding: [17-20].

### 34. Distribution-Shift Anomaly

The probability distribution generating observations changes materially. Any combination of location, scale, shape, tails, modality, or category probabilities may change.

Distribution shift is broader than a mean or variance shift. It is often measured through divergence, distance, two-sample tests, or classifier-based comparisons.

### 35. Covariate Shift

The distribution of input variables changes while the conditional relationship between inputs and outcomes remains approximately stable. Formally, `P(X)` changes while `P(Y | X)` remains stable.

Covariate shift matters because a model may be applied to regions of the input space that were rare or absent during training.

### 36. Prior-Probability Shift

The distribution of outcome classes changes while the class-conditional input distributions remain approximately stable. Formally, `P(Y)` changes while `P(X | Y)` remains stable.

This shift changes expected prevalence and can make previously calibrated probabilities inaccurate even if class-specific patterns have not changed.

### 37. Concept Drift

The relationship between inputs and outcomes changes over time. Formally, `P(Y | X)` changes, meaning the same input pattern no longer implies the same expected outcome.

Concept drift directly degrades predictive models. It may be sudden, gradual, incremental, recurring, or localized to part of the feature space.

### 38. Gradual Drift

A distribution or model relationship changes slowly over an extended period. No single observation or boundary is strongly anomalous, but cumulative movement becomes substantial.

Gradual drift is difficult to distinguish from normal adaptation and requires comparison across sufficiently separated windows.

### 39. Sudden Drift

A distribution or relationship changes abruptly between adjacent periods. Sudden drift resembles a change point but emphasizes replacement of the underlying data-generating process.

Detection speed and false-alarm control are central because little post-change data may initially be available.

### 40. Recurring or Seasonal Drift

A previously observed distribution or regime returns after an interval. The process alternates among known states rather than moving permanently in one direction.

Models that forget old regimes too aggressively may repeatedly misclassify recurring states as novel.

### 41. Tail Anomaly

An observation or group exhibits unusual behavior specifically in the extreme tail of a distribution. Tail anomalies concern rare extremes whose probabilities are poorly estimated by central-distribution models.

Extreme-value methods are often appropriate. Heavy-tailed data require special care because apparently extreme observations may be expected more often than Gaussian assumptions suggest.

### 42. Modality Anomaly

The number, location, size, or shape of modes in a distribution changes unexpectedly. A new cluster may emerge, an existing mode may disappear, or modes may merge or split.

Summary statistics such as mean and variance can completely miss modality anomalies.

### 43. Entropy Anomaly

The uncertainty, diversity, or concentration of a distribution changes unexpectedly. Entropy may rise when outcomes become more dispersed or fall when they become unusually concentrated.

Entropy anomalies are useful for categorical and probabilistic data but can be sensitive to binning, sample size, and estimation method.

### 44. Dispersion Anomaly

The spread of observations differs from expectation. This includes changes in variance, interquartile range, median absolute deviation, or another dispersion measure.

Unlike a variance-shift anomaly, dispersion anomalies may be evaluated outside a time-series setting, such as across groups or batches.

### 45. Skewness Anomaly

The asymmetry of a distribution changes unexpectedly. The center and total variability may remain similar while one tail becomes more pronounced.

Skewness estimates are sensitive to extremes and require adequate sample size. Robust quantile-based asymmetry measures may be preferable.

### 46. Kurtosis or Tail-Weight Anomaly

The concentration around the center or weight of the tails changes unexpectedly. A distribution may begin producing extremes more frequently without a major change in variance.

Classical kurtosis is highly sensitive to outliers, so its interpretation should be supported by robust tail diagnostics.

### 47. Quantile Anomaly

One or more quantiles shift unexpectedly even when aggregate statistics remain stable. Different parts of a distribution may move independently.

Quantile anomalies are useful for detecting changes concentrated in the lower tail, median, upper tail, or another percentile range.

## Multivariate and Geometric Anomalies

Academic grounding: [2, 5-9, 21-23].

### 48. Multivariate Combination Anomaly

An observation contains a combination of feature values that is unusual jointly, even though every individual feature value is common. The anomaly lies in the joint distribution.

Univariate rules cannot detect these anomalies. Analysis must model covariance, dependence, density, distance, or a learned multivariate representation.

### 49. Correlation Anomaly

The relationship between two or more variables differs from its expected pattern. Variables may stop moving together, become newly correlated, reverse association, or change correlation strength.

Correlation anomalies can occur without anomalous marginal distributions. Correlation does not imply causation, and changes may be driven by a third variable.

### 50. Covariance-Structure Anomaly

The complete pattern of joint variability among multiple variables changes. This extends correlation anomalies to changes in scale and multivariate dependence structure.

Covariance anomalies are important in high-dimensional systems but require sufficient observations for stable estimation.

### 51. Distance-Based Anomaly

An observation is anomalous because it is far from most other observations under a chosen distance metric. Distance may be measured in the original feature space or a transformed representation.

Results depend heavily on scaling, feature selection, and the distance metric. In high dimensions, distances may become less discriminative.

### 52. Density-Based Anomaly

An observation lies in a region of unusually low estimated probability density. Density-based methods can recognize anomalies that are not necessarily far from the global center.

Density estimation becomes difficult in high dimensions and can confuse sparse but legitimate subpopulations with anomalies.

### 53. Cluster Anomaly

An observation, small cluster, or entire cluster is unusual relative to the clustering structure. It may be distant from established clusters, belong weakly to every cluster, or form a tiny isolated cluster.

Cluster anomalies depend on the assumed cluster model. Rare clusters are not automatically anomalous if they represent legitimate minority populations.

### 54. Boundary Anomaly

An observation lies unusually close to, crosses, or destabilizes an expected decision or support boundary. It may occupy a region where class membership or process state is highly ambiguous.

Boundary anomalies are relevant when the normal region has a meaningful learned boundary, but they can also reflect ordinary uncertainty rather than true abnormality.

### 55. Manifold Anomaly

An observation lies away from the lower-dimensional manifold on which normal high-dimensional data are concentrated. Its individual coordinates may look normal while their geometric combination violates the learned structure.

Manifold anomalies require a representative sample of normal geometry and can be sensitive to representation-learning errors.

### 56. Reconstruction Anomaly

A model trained to reconstruct typical observations produces unusually high reconstruction error for a new observation. The anomaly is defined by failure to represent the observation using learned normal patterns.

High reconstruction error can indicate novelty, but overly flexible models may reconstruct anomalies well, while poorly trained models may fail on legitimate data.

### 57. Latent-Space Anomaly

An observation has an unusual position or probability in a learned latent representation. The latent space may summarize complex nonlinear relationships from the original data.

Interpretability is a major limitation because anomalous latent coordinates may not map clearly back to observable features.

### 58. Leverage-Point Anomaly

An observation has unusual predictor values and therefore exerts disproportionate influence on a fitted model. A leverage point may or may not have a large residual.

High leverage is not inherently erroneous. Such observations may contain valuable information about poorly sampled regions of the predictor space.

### 59. Influential-Observation Anomaly

Removing an observation substantially changes estimated parameters, predictions, or conclusions. Influence combines aspects of leverage and residual size.

Influential observations deserve investigation because they can dominate results, but they may be valid and substantively important.

## Sequential and Process Anomalies

Academic grounding: [1, 2, 12, 24, 25].

### 60. Sequence-Order Anomaly

Events occur in an unusual order even though the individual events are common. The anomaly is defined by the ordering relation.

Sequence-order anomalies require a model of expected transitions or permissible orderings. They may be hidden when events are analyzed independently.

### 61. Transition Anomaly

A transition from one state or event type to another is unusually improbable. The states themselves may be normal, but the edge between them is rare.

Transition anomalies are commonly modeled using transition matrices, Markov models, state machines, or conditional sequence models.

### 62. Repetition Anomaly

An event, symbol, state, or subsequence repeats an unusual number of times. The anomaly may be excessive repetition or unexpectedly missing repetition.

Repetition should be evaluated relative to expected sequence length and normal recurrence behavior.

### 63. Sequence-Length Anomaly

A complete sequence contains an unusually large or small number of events. The event composition and ordering may otherwise be normal.

Length anomalies require comparable sequence boundaries and can be confounded by truncation or incomplete observation.

### 64. Path Anomaly

A trajectory through a state space, process, or network follows an unusual route. Individual transitions may be common while the complete path is rare.

Path anomalies require a model of typical routes and should account for path length, alternative routes, and endpoint frequency.

### 65. Process-Conformance Anomaly

An observed process instance violates or deviates from an expected process model. Deviations may include skipped states, unexpected states, rework loops, timing violations, or forbidden transitions.

The reference process may be prescribed or learned. A rigid reference model can incorrectly label legitimate process variation as anomalous.

### 66. Motif Anomaly

A recurring local pattern or motif appears with unusual frequency, disappears, or has an unusual structure. Motifs may occur in sequences, time series, graphs, or spatial data.

Motif anomalies focus on repeated structural units rather than entire observations or processes.

### 67. Event-Composition Anomaly

A sequence or group contains an unusual mixture of event types, even if its total length and ordering are not unusual.

Composition anomalies are often evaluated using category proportions, divergence measures, or topic-like representations.

## Graph and Relationship Anomalies

Academic grounding: [26-30].

### 68. Node Anomaly

A node has unusual attributes, connectivity, position, or behavior relative to other nodes. Its anomaly may arise from its features, graph structure, or both.

Appropriate comparisons often depend on node type and role because different classes of nodes naturally have different connectivity patterns.

### 69. Edge Anomaly

A relationship between two nodes is unusual because it is new, rare, unexpected, unusually weighted, or inconsistent with node attributes.

Edge anomalies require a model of expected relationships. A globally rare edge may still be normal for a particular pair of node types.

### 70. Subgraph Anomaly

A connected group of nodes and edges has an unusual internal structure or relationship to the larger graph. Individual nodes and edges may not appear anomalous independently.

Examples of anomalous properties include density, topology, attribute composition, or connectivity to the rest of the graph.

### 71. Community Anomaly

A graph community has unusual structure, membership, behavior, or evolution relative to other communities. It may be unusually dense, sparse, isolated, mixed, or unstable.

Community anomalies depend on the selected community-detection method and can change as graph resolution changes.

### 72. Degree Anomaly

A node has an unusually high or low number of connections relative to comparable nodes. Weighted degree or type-specific degree may be more informative than raw degree.

Degree anomalies are simple and interpretable but may miss unusual relationship patterns with normal connection counts.

### 73. Centrality Anomaly

A node's importance or structural role is unusual according to a centrality measure such as betweenness, closeness, or eigenvector centrality (including variants such as PageRank for directed graphs).

Different centrality measures capture different meanings. Anomaly claims must state which structural role is unexpectedly strong or weak.

### 74. Graph-Path-Length Anomaly

The distance between nodes, or the route used to connect them, is unusually short, long, or improbable. This can indicate unexpected reachability or separation.

Path-length anomalies require a stable definition of allowed edge types, direction, and weights.

### 75. Graph-Evolution Anomaly

The graph changes unusually over time. Nodes, edges, communities, or structural metrics may appear, disappear, merge, split, or rewire at unexpected rates.

This anomaly requires temporal snapshots or event-based graph updates and should distinguish ordinary churn from structural change.

### 76. Bipartite-Relationship Anomaly

An unusual association appears between two distinct classes of entities in a bipartite graph. The anomaly can involve a rare edge, unusual neighborhood overlap, or atypical matching pattern.

Bipartite models preserve entity-type distinctions that would be lost in a single homogeneous graph.

### 77. Fan-In Anomaly

An unusually large or small number of source nodes connect to a destination node within a relevant period or context.

Fan-in anomalies are degree anomalies with a directional and often temporal interpretation.

### 78. Fan-Out Anomaly

A source node connects to an unusually large or small number of destination nodes within a relevant period or context.

Fan-out should be normalized by the source node's role, activity level, and expected opportunity to create connections.

## Spatial and Spatiotemporal Anomalies

Academic grounding: [2, 31-33].

### 79. Spatial Point Anomaly

An observation occurs at an unusual location relative to the spatial distribution of observations. It may be isolated, far from clusters, or located in a low-density region.

Distance metrics should respect the geometry of the space, and heterogeneous spatial density should be handled explicitly.

### 80. Spatial-Context Anomaly

A measured value is unusual for its location even though the value is normal globally. The anomaly is conditional on spatial context.

Spatial autocorrelation and regional differences must be modeled to avoid treating legitimate geographic variation as anomalous.

### 81. Spatial Cluster Anomaly

A geographic or geometric region contains an unusual concentration or scarcity of observations. The anomaly concerns the region as a collective.

Spatial scan methods often compare observed and expected counts while accounting for population or exposure.

### 82. Trajectory Anomaly

A moving entity follows an unusual route, speed profile, direction, stop pattern, or destination sequence.

Trajectory anomalies combine spatial and temporal structure. They require normalization for trip purpose, origin, destination, and environmental constraints.

### 83. Spatiotemporal Anomaly

An observation or cluster is unusual only when both location and time are considered jointly. A normal event at a normal location may still be anomalous at a particular time.

These anomalies require models that represent spatial dependence, temporal dependence, and their interaction.

## Categorical, Textual, and Structured-Data Anomalies

Academic grounding: [2, 34, 35].

### 84. Rare-Category Anomaly

A categorical value appears with unusually low frequency. The rarity may be global, contextual, entity-specific, or peer-relative.

Rare categories are not automatically anomalous. Statistical treatment should account for expected long-tail behavior and sample size.

### 85. Novel-Category Anomaly

A previously unseen categorical value appears. This is a special case of novelty detection where the observation lies outside the known category vocabulary.

Novel categories may represent genuine new states, data-entry variation, schema evolution, or errors.

### 86. Category-Combination Anomaly

A combination of individually common categorical values is rare or previously unseen. The anomaly lies in co-occurrence rather than in any single category.

Contingency models, association analysis, and probabilistic graphical models can represent expected combinations.

### 87. Categorical-Distribution Anomaly

The frequency distribution across categories changes unexpectedly. New dominance, loss of diversity, or shifts among categories may occur without any novel category.

Evaluation should account for sample size and distinguish random multinomial variation from substantive change.

### 88. Textual-Likelihood Anomaly

A text sequence has unusually low probability under a language or token model. The anomaly may arise from vocabulary, syntax, style, semantics, or token ordering.

Low likelihood can reflect novelty, another language, specialized terminology, corruption, or model limitations rather than true abnormality.

### 89. Semantic Anomaly

An observation's meaning is inconsistent with the expected semantic context, even if its surface form is common. Semantic anomalies depend on representations of meaning rather than exact values.

They are difficult to interpret and sensitive to the quality and domain coverage of the semantic model.

### 90. Schema Anomaly

The structure of a record differs from the expected schema. Fields may be missing, added, renamed, moved, nested differently, or assigned unexpected types.

Schema anomalies may indicate valid evolution or data-quality problems. They should be separated from behavioral anomalies in the values themselves.

## Cross-Source and Cross-View Anomalies

Academic grounding: [36, 37].

### 91. Cross-Source Inconsistency Anomaly

Two or more data sources that should agree provide incompatible observations. The anomaly is a contradiction across sources.

Reliable detection requires entity resolution, aligned timestamps, comparable definitions, and an explicit model of expected agreement.

### 92. Missing-Correspondence Anomaly

An observation appears in one source without an expected corresponding observation in another source. This is a cross-source negative anomaly.

The expected correspondence and acceptable delay must be defined carefully because collection gaps can mimic the same pattern.

### 93. Cross-View Anomaly

An entity appears normal under each individual representation but inconsistent when multiple views are considered jointly. Views may contain different feature sets, modalities, or measurement systems.

Cross-view analysis is useful when no single source captures the full structure of normal behavior.

### 94. Multimodal Anomaly

Data from different modalities form an unusual combination, such as an unexpected pairing between numeric, categorical, textual, image, audio, or temporal representations.

Multimodal anomalies require aligned observations and a model of normal cross-modal dependence.

## Model, Prediction, and Uncertainty Anomalies

Academic grounding: [5, 9, 20, 38-41].

### 95. Prediction-Confidence Anomaly

A model produces unusually low confidence, high uncertainty, or disagreement among plausible predictions. The input may be outside well-supported regions of the training distribution.

Low confidence is not the same as anomaly, but it is a useful indicator that the model lacks a reliable basis for prediction.

### 96. Out-of-Distribution Anomaly

An observation is generated from a distribution meaningfully different from the model's training distribution. It may still resemble known data superficially while violating deeper learned structure.

Out-of-distribution detection is broader than class novelty because the observation may belong to a known class under changed conditions.

### 97. Novelty Anomaly

A valid but previously unobserved pattern appears outside the known normal set. Novelty detection typically assumes that training data represent normal behavior and asks whether new observations belong to that normal distribution.

Novelty differs from generic outlier detection because training data are usually expected to be relatively uncontaminated.

### 98. Model-Disagreement Anomaly

Multiple models, estimators, or measurement methods produce unusually inconsistent results for the same observation. The disagreement itself is treated as an anomaly signal.

Disagreement may identify ambiguous, novel, or poorly measured cases, but it can also arise from correlated model weaknesses or inconsistent preprocessing.

### 99. Calibration Anomaly

Observed outcome frequencies no longer match predicted probabilities. For example, events assigned a certain predicted probability occur much more or less frequently than expected.

Calibration anomalies indicate that uncertainty estimates or probabilities are no longer reliable, even when ranking performance remains acceptable.

### 100. Uncertainty-Structure Anomaly

The magnitude, distribution, or source of uncertainty changes unexpectedly. Measurement noise, predictive variance, or disagreement may increase, decrease, or become concentrated in new regions.

This anomaly can reveal changing data quality, model degradation, or a transition into unfamiliar operating conditions.

## Data-Quality and Measurement Anomalies

Academic grounding: [3, 42-45].

### 101. Missingness Anomaly

Values are missing at an unusual rate, in an unusual pattern, or under unusual conditions. Missingness can itself carry information and may not be random.

Analysis should distinguish missing completely at random, missing at random conditional on observed variables, and missing not at random.

### 102. Sampling-Rate Anomaly

The frequency or pattern at which observations are collected changes unexpectedly. Apparent changes in the measured process may actually result from altered sampling.

Sampling anomalies must be identified before interpreting count, rate, timing, or distribution anomalies.

### 103. Measurement-Error Anomaly

A value is implausible because of sensor error, recording error, transformation error, or unit mismatch rather than a genuine change in the underlying process.

Statistical detection may use physical constraints, redundancy, smoothness, or cross-source consistency, but determining the cause often requires metadata.

### 104. Precision or Resolution Anomaly

The granularity, rounding, or numerical precision of measurements changes unexpectedly. Values may become unusually quantized, truncated, or precise.

This can alter distributions and create artificial patterns that resemble behavioral change.

### 105. Duplicate Anomaly

Observations are repeated unexpectedly, either exactly or approximately. Duplicate anomalies can inflate counts, distort distributions, and create false sequence patterns.

Duplicate detection must define whether repeated observations are impossible, unlikely, or legitimate repeated events.

### 106. Timestamp Anomaly

Timestamps are missing, duplicated, out of order, implausibly distant, or inconsistent across sources. The underlying observation may be valid while its temporal metadata are anomalous.

Timestamp anomalies can invalidate sequence, rate, and time-series analyses if not corrected first.

### 107. Unit or Scale Anomaly

Measurements use an unexpected unit, scale, transformation, or magnitude convention. The resulting values may appear extreme but are not substantively anomalous.

Unit anomalies often create abrupt multiplicative shifts and should be checked before concluding that a process changed.

### 108. Censoring or Truncation Anomaly

The observed data become unexpectedly limited by detection bounds, reporting caps, selection criteria, or incomplete observation windows.

Censoring changes the visible distribution without necessarily changing the underlying process. Statistical models must represent the observation mechanism.

## Composite and Higher-Order Anomalies

Academic grounding: [2, 4, 5, 23, 46-48].

### 109. Multi-Signal Composite Anomaly

Several individually weak deviations combine into a statistically unusual joint state. No single signal is sufficient, but their co-occurrence produces strong evidence against the reference model.

Composite anomalies require principled score combination and controls for dependence among signals to avoid overstating evidence.

### 110. Hierarchical Anomaly

An anomaly occurs at one or more levels of a hierarchy, such as observation, entity, subgroup, region, or population. A lower-level anomaly may aggregate into a higher-level anomaly, or a group may be anomalous despite normal members.

Hierarchical models help separate variation attributable to each level and identify where the deviation originates.

### 111. Persistent Anomaly

A deviation remains anomalous across multiple observations or periods. Persistence distinguishes sustained abnormal behavior from transient noise.

Persistence can be defined through consecutive exceedances, accumulated anomaly score, or time spent outside an expected state.

### 112. Transient Anomaly

A deviation is brief and returns quickly to the reference regime. Transient anomalies include spikes, dips, short bursts, and temporary structural disruptions.

Their importance depends on duration, magnitude, and the normal short-term volatility of the process.

### 113. Emerging Anomaly

A weak deviation grows over time and becomes increasingly distinguishable from normal behavior. Early observations may not individually meet an anomaly threshold.

Emerging anomalies require accumulation methods that detect consistent directional evidence without waiting for a fully developed extreme.

### 114. Cascading Anomaly

An anomaly in one component, variable, or level propagates through related components and produces a structured series of secondary deviations.

The statistical challenge is distinguishing propagation from independent coincident anomalies and identifying the earliest anomalous source.

### 115. Compensating Anomaly

Multiple unusual changes offset one another in aggregate statistics. For example, one component rises while another falls, leaving the total apparently normal.

Compensating anomalies demonstrate why aggregate monitoring alone can miss substantial internal redistribution.

### 116. Masked Anomaly

An anomalous observation is hidden because other anomalies, high variance, aggregation, or model contamination make it appear normal.

Masking is a major problem in non-robust estimation because anomalies can alter the reference model used to detect themselves.

### 117. Swamping Anomaly Effect

Normal observations are incorrectly classified as anomalous because true anomalies distort the estimated reference distribution or model.

Swamping is the counterpart to masking. Robust estimation and iterative analysis can reduce both effects.

### 118. Adversarially Induced Statistical Anomaly

Observations are deliberately constructed to alter, evade, or exploit a statistical model. This includes gradual contamination, crafted boundary cases, and manipulation of reference data.

From a purely statistical perspective, the defining feature is that the data-generating process responds strategically to the detector rather than remaining passive.

## Cybersecurity Activity Examples

The following examples show how statistical anomaly types can explain observable suspicious or malicious activity. These links lead to the [activity-to-anomaly mapping catalog](attack-statistical-anomaly-mapping.md), where each activity is described in terms of its comparison unit, expected behavior, measurable deviation, ATT&CK technique, and evidence sources. Statistical deviation is supporting evidence, not proof of malicious intent.

| Statistical anomaly type | Linked suspicious or malicious activity examples |
|---|---|
| [Collective Anomaly](#4-collective-anomaly) | [Low-volume password failures distributed across many accounts](attack-statistical-anomaly-mapping.md#password-spraying) |
| [Conditional Anomaly](#5-conditional-anomaly) | [Trusted system binary launches unexpected content](attack-statistical-anomaly-mapping.md#trusted-binary-proxy-execution), [object renamed to resemble a trusted object](attack-statistical-anomaly-mapping.md#masquerading), [protected credential resource accessed by an unusual process](attack-statistical-anomaly-mapping.md#credential-dumping) |
| [Self-Baseline Anomaly](#7-self-baseline-anomaly) | [Valid credentials used from an unexpected context](attack-statistical-anomaly-mapping.md#valid-account-abuse), [command interpreter execution outside a host or user's normal pattern](attack-statistical-anomaly-mapping.md#command-interpreter-execution), [new autostart configuration](attack-statistical-anomaly-mapping.md#autostart-change) |
| [Peer-Group Anomaly](#8-peer-group-anomaly) | [Unexpected container administration command](attack-statistical-anomaly-mapping.md#container-exec), [privileged container unlike peer workloads](attack-statistical-anomaly-mapping.md#privileged-container), [cloud-resource enumeration unlike role peers](attack-statistical-anomaly-mapping.md#cloud-enumeration) |
| [Population Anomaly](#9-population-anomaly) | [Synchronized behavioral change after a compromised software installation](attack-statistical-anomaly-mapping.md#supply-chain-installation) |
| [Count Anomaly](#13-count-anomaly) | [Unusually many public web paths requested in a session](attack-statistical-anomaly-mapping.md#public-web-enumeration) |
| [Rate Anomaly](#14-rate-anomaly) | [External service scanning](attack-statistical-anomaly-mapping.md#external-service-scanning), [password guessing](attack-statistical-anomaly-mapping.md#password-guessing), [internal service scanning](attack-statistical-anomaly-mapping.md#internal-service-scanning), [service disruption](attack-statistical-anomaly-mapping.md#service-disruption) |
| [Volume Anomaly](#15-volume-anomaly) | [DNS enumeration](attack-statistical-anomaly-mapping.md#dns-enumeration), [bulk data access](attack-statistical-anomaly-mapping.md#bulk-data-access), [large outbound transfer](attack-statistical-anomaly-mapping.md#large-outbound-transfer), [data destruction](attack-statistical-anomaly-mapping.md#data-destruction) |
| [Burst Anomaly](#16-burst-anomaly) | [Repeated MFA prompts](attack-statistical-anomaly-mapping.md#mfa-fatigue), [service-ticket request burst](attack-statistical-anomaly-mapping.md#kerberoasting), [sudden secret retrieval](attack-statistical-anomaly-mapping.md#secret-retrieval) |
| [Drought or Silence Anomaly](#17-drought-or-silence-anomaly) | [Indicator or telemetry removal](attack-statistical-anomaly-mapping.md#indicator-removal), [security sensor or logging disabled](attack-statistical-anomaly-mapping.md#tool-disablement) |
| [Duration Anomaly](#18-duration-anomaly) | [External remote-service session with unusual duration](attack-statistical-anomaly-mapping.md#external-remote-session) |
| [Inter-Arrival-Time Anomaly](#19-inter-arrival-time-anomaly) | [Repeated MFA prompts](attack-statistical-anomaly-mapping.md#mfa-fatigue), [periodic command-and-control communication](attack-statistical-anomaly-mapping.md#periodic-c2) |
| [Ratio or Proportion Anomaly](#20-ratio-or-proportion-anomaly) | [Abnormal web response-code composition](attack-statistical-anomaly-mapping.md#public-web-enumeration), [password-guessing failure ratio](attack-statistical-anomaly-mapping.md#password-guessing), [MFA denial ratio](attack-statistical-anomaly-mapping.md#mfa-fatigue) |
| [Temporal-Context Anomaly](#21-temporal-context-anomaly) | [Valid-account use at an unusual time](attack-statistical-anomaly-mapping.md#valid-account-abuse), [external remote session outside normal hours](attack-statistical-anomaly-mapping.md#external-remote-session), [unexpected serverless invocation](attack-statistical-anomaly-mapping.md#serverless-execution) |
| [Level-Shift Anomaly](#23-level-shift-anomaly) | [Security telemetry drops to zero](attack-statistical-anomaly-mapping.md#tool-disablement), [sustained bulk data access](attack-statistical-anomaly-mapping.md#bulk-data-access), [resource hijacking](attack-statistical-anomaly-mapping.md#resource-hijacking) |
| [Change-Point Anomaly](#25-change-point-anomaly) | [Startup or logon configuration abruptly changes](attack-statistical-anomaly-mapping.md#autostart-change) |
| [Periodicity Anomaly](#27-periodicity-anomaly) | [Low-and-slow exfiltration](attack-statistical-anomaly-mapping.md#low-and-slow-exfiltration), [periodic command-and-control communication](attack-statistical-anomaly-mapping.md#periodic-c2) |
| [Phase Anomaly](#28-phase-anomaly) | [Scheduled execution occurs at a changed phase](attack-statistical-anomaly-mapping.md#scheduled-execution) |
| [Subsequence Anomaly](#30-subsequence-anomaly) | [Unusual DNS command-and-control query sequence](attack-statistical-anomaly-mapping.md#dns-c2) |
| [Autocorrelation Anomaly](#32-autocorrelation-anomaly) | [Repeated low-and-slow exfiltration](attack-statistical-anomaly-mapping.md#low-and-slow-exfiltration), [periodic command-and-control communication](attack-statistical-anomaly-mapping.md#periodic-c2) |
| [Synchronization Anomaly](#33-synchronization-anomaly) | [Compromised software produces synchronized endpoint changes](attack-statistical-anomaly-mapping.md#supply-chain-installation), [synchronized service errors during disruption](attack-statistical-anomaly-mapping.md#service-disruption) |
| [Distribution-Shift Anomaly](#34-distribution-shift-anomaly) | [DNS enumeration changes query distribution](attack-statistical-anomaly-mapping.md#dns-enumeration), [obfuscated content changes character distribution](attack-statistical-anomaly-mapping.md#obfuscated-content), [firewall policy shifts toward permissive rules](attack-statistical-anomaly-mapping.md#firewall-impairment) |
| [Tail Anomaly](#41-tail-anomaly) | [Obfuscated content with extreme entropy](attack-statistical-anomaly-mapping.md#obfuscated-content), [large outbound transfer](attack-statistical-anomaly-mapping.md#large-outbound-transfer), [resource hijacking with extreme consumption](attack-statistical-anomaly-mapping.md#resource-hijacking) |
| [Entropy Anomaly](#43-entropy-anomaly) | [Encoded or obfuscated content](attack-statistical-anomaly-mapping.md#obfuscated-content), [DNS carrying encoded command-and-control data](attack-statistical-anomaly-mapping.md#dns-c2) |
| [Multivariate Combination Anomaly](#48-multivariate-combination-anomaly) | [Phishing message with unusual combined features](attack-statistical-anomaly-mapping.md#phishing-delivery), [valid-account use from an unexpected context](attack-statistical-anomaly-mapping.md#valid-account-abuse), [privileged container with an unusual runtime profile](attack-statistical-anomaly-mapping.md#privileged-container) |
| [Sequence-Order Anomaly](#60-sequence-order-anomaly) | [Delivered content followed by process execution](attack-statistical-anomaly-mapping.md#phishing-execution-sequence), [PowerShell abuse sequence](attack-statistical-anomaly-mapping.md#powershell-abuse), [lateral tool transfer followed by execution](attack-statistical-anomaly-mapping.md#lateral-tool-transfer) |
| [Transition Anomaly](#61-transition-anomaly) | [Public request followed by an application child process](attack-statistical-anomaly-mapping.md#public-app-exploitation), [process injection write-to-execution transition](attack-statistical-anomaly-mapping.md#process-injection), [data collection followed by staging](attack-statistical-anomaly-mapping.md#data-staging) |
| [Edge Anomaly](#69-edge-anomaly) | [First-seen sender-recipient relationship](attack-statistical-anomaly-mapping.md#phishing-delivery), [new privilege relationship](attack-statistical-anomaly-mapping.md#account-manipulation), [new lateral-administration path](attack-statistical-anomaly-mapping.md#remote-service-lateral-movement), [new exfiltration destination](attack-statistical-anomaly-mapping.md#web-service-exfiltration) |
| [Subgraph Anomaly](#70-subgraph-anomaly) | [Unusual process-injection relationship pattern](attack-statistical-anomaly-mapping.md#process-injection) |
| [Graph-Path-Length Anomaly](#74-graph-path-length-anomaly) | [Unexpected path to privilege](attack-statistical-anomaly-mapping.md#account-manipulation), [unusual lateral-administration path](attack-statistical-anomaly-mapping.md#remote-service-lateral-movement) |
| [Graph-Evolution Anomaly](#75-graph-evolution-anomaly) | [Privilege graph abruptly restructures](attack-statistical-anomaly-mapping.md#account-manipulation), [password spraying expands the authentication graph](attack-statistical-anomaly-mapping.md#password-spraying), [internal scanning rapidly grows the communication graph](attack-statistical-anomaly-mapping.md#internal-service-scanning) |
| [Fan-Out Anomaly](#78-fan-out-anomaly) | [External service scanning](attack-statistical-anomaly-mapping.md#external-service-scanning), [password spraying](attack-statistical-anomaly-mapping.md#password-spraying), [account enumeration](attack-statistical-anomaly-mapping.md#account-enumeration), [lateral movement across many systems](attack-statistical-anomaly-mapping.md#remote-service-lateral-movement) |
| [Rare-Category Anomaly](#84-rare-category-anomaly) | [Rare DNS query type during enumeration](attack-statistical-anomaly-mapping.md#dns-enumeration), [rare command-interpreter argument pattern](attack-statistical-anomaly-mapping.md#command-interpreter-execution), [unusual service-ticket encryption category](attack-statistical-anomaly-mapping.md#kerberoasting) |
| [Novel-Category Anomaly](#85-novel-category-anomaly) | [First-seen PowerShell script feature](attack-statistical-anomaly-mapping.md#powershell-abuse), [new system service](attack-statistical-anomaly-mapping.md#service-persistence), [new forwarding destination](attack-statistical-anomaly-mapping.md#mail-forwarding-rule) |
| [Category-Combination Anomaly](#86-category-combination-anomaly) | [Unexpected package-publisher combination](attack-statistical-anomaly-mapping.md#supply-chain-installation), [trusted binary in an unusual execution context](attack-statistical-anomaly-mapping.md#trusted-binary-proxy-execution), [unusual process-path archive creation](attack-statistical-anomaly-mapping.md#data-staging) |
| [Categorical-Distribution Anomaly](#87-categorical-distribution-anomaly) | [Public web enumeration changes response-code composition](attack-statistical-anomaly-mapping.md#public-web-enumeration), [cloud enumeration changes API action mix](attack-statistical-anomaly-mapping.md#cloud-enumeration), [ransomware changes file-extension distribution](attack-statistical-anomaly-mapping.md#ransomware-encryption) |
| [Cross-Source Inconsistency Anomaly](#91-cross-source-inconsistency-anomaly) | [Message or file activity followed by unexpected process execution](attack-statistical-anomaly-mapping.md#phishing-execution-sequence) |
| [Missing-Correspondence Anomaly](#92-missing-correspondence-anomaly) | [Expected telemetry disappears after indicator removal](attack-statistical-anomaly-mapping.md#indicator-removal), [sensor heartbeat disappears after tool disablement](attack-statistical-anomaly-mapping.md#tool-disablement), [expected backup does not occur](attack-statistical-anomaly-mapping.md#recovery-impairment) |
| [Persistent Anomaly](#111-persistent-anomaly) | [Repeated low-and-slow exfiltration](attack-statistical-anomaly-mapping.md#low-and-slow-exfiltration), [persistent web-service command-and-control traffic](attack-statistical-anomaly-mapping.md#web-service-c2) |
| [Emerging Anomaly](#113-emerging-anomaly) | [Resource hijacking produces an emerging consumption trend](attack-statistical-anomaly-mapping.md#resource-hijacking) |
| [Cascading Anomaly](#114-cascading-anomaly) | [Ransomware encryption spreads across directories](attack-statistical-anomaly-mapping.md#ransomware-encryption) |

## Interpretation Principles

1. **Anomaly does not mean error.** An unusual observation can be valid, important, or expected under an unmodeled context.
2. **Anomaly does not mean harmful.** Statistical deviation describes improbability or inconsistency, not value judgment.
3. **Rarity alone is insufficient.** Rare observations may belong to legitimate minority populations or heavy-tailed distributions.
4. **The baseline defines the anomaly.** A result is meaningful only when the reference population, context, window, and assumptions are explicit.
5. **Multiple labels may apply.** An anomaly can belong to several categories because each category describes a different statistical property.
6. **Model failure can resemble anomaly.** Misspecification, drift, missing variables, and measurement errors must be investigated.
7. **Aggregation can hide anomalies.** Group-level stability can conceal offsetting or localized deviations.
8. **High-dimensional data require structure.** Distance and density become unreliable without suitable scaling, feature selection, or representation learning.
9. **Time changes expectations.** Stationarity should not be assumed when trends, cycles, regimes, or drift are plausible.
10. **Statistical significance is not practical significance.** Large samples can make negligible deviations statistically detectable.

## Academic References

1. Chandola, V., Banerjee, A., and Kumar, V. (2009). Anomaly detection: A survey. *ACM Computing Surveys*, 41(3), Article 15. https://doi.org/10.1145/1541880.1541882
2. Aggarwal, C. C. (2017). *Outlier Analysis* (2nd ed.). Springer. https://doi.org/10.1007/978-3-319-47578-3
3. Barnett, V., and Lewis, T. (1994). *Outliers in Statistical Data* (3rd ed.). Wiley.
4. Hodge, V. J., and Austin, J. (2004). A survey of outlier detection methodologies. *Artificial Intelligence Review*, 22, 85-126. https://doi.org/10.1023/B:AIRE.0000045502.10941.a9
5. Pang, G., Shen, C., Cao, L., and van den Hengel, A. (2021). Deep learning for anomaly detection: A review. *ACM Computing Surveys*, 54(2), Article 38. https://doi.org/10.1145/3439950
6. Knorr, E. M., and Ng, R. T. (1998). Algorithms for mining distance-based outliers in large datasets. In *Proceedings of the 24th International Conference on Very Large Data Bases*, 392-403.
7. Breunig, M. M., Kriegel, H.-P., Ng, R. T., and Sander, J. (2000). LOF: Identifying density-based local outliers. In *Proceedings of the 2000 ACM SIGMOD International Conference on Management of Data*, 93-104. https://doi.org/10.1145/335191.335388
8. Schubert, E., Zimek, A., and Kriegel, H.-P. (2014). Local outlier detection reconsidered: A generalized view on locality with applications to spatial, video, and network outlier detection. *Data Mining and Knowledge Discovery*, 28, 190-237. https://doi.org/10.1007/s10618-012-0300-z
9. Pimentel, M. A. F., Clifton, D. A., Clifton, L., and Tarassenko, L. (2014). A review of novelty detection. *Signal Processing*, 99, 215-249. https://doi.org/10.1016/j.sigpro.2013.12.026
10. Cameron, A. C., and Trivedi, P. K. (2013). *Regression Analysis of Count Data* (2nd ed.). Cambridge University Press. https://doi.org/10.1017/CBO9781139013567
11. Cook, R. J., and Lawless, J. F. (2007). *The Statistical Analysis of Recurrent Events*. Springer. https://doi.org/10.1007/978-0-387-69810-6
12. Gupta, M., Gao, J., Aggarwal, C. C., and Han, J. (2014). Outlier detection for temporal data: A survey. *IEEE Transactions on Knowledge and Data Engineering*, 26(9), 2250-2267. https://doi.org/10.1109/TKDE.2013.184
13. Blázquez-García, A., Conde, A., Mori, U., and Lozano, J. A. (2021). A review on outlier/anomaly detection in time series data. *ACM Computing Surveys*, 54(3), Article 56. https://doi.org/10.1145/3444690
14. Truong, C., Oudre, L., and Vayatis, N. (2020). Selective review of offline change point detection methods. *Signal Processing*, 167, 107299. https://doi.org/10.1016/j.sigpro.2019.107299
15. Torrence, C., and Compo, G. P. (1998). A practical guide to wavelet analysis. *Bulletin of the American Meteorological Society*, 79(1), 61-78. https://doi.org/10.1175/1520-0477(1998)079%3C0061:APGTWA%3E2.0.CO;2
16. Hyndman, R. J., and Athanasopoulos, G. (2021). *Forecasting: Principles and Practice* (3rd ed.). OTexts. https://otexts.com/fpp3/
17. Gama, J., Žliobaitė, I., Bifet, A., Pechenizkiy, M., and Bouchachia, A. (2014). A survey on concept drift adaptation. *ACM Computing Surveys*, 46(4), Article 44. https://doi.org/10.1145/2523813
18. Moreno-Torres, J. G., Raeder, T., Alaiz-Rodríguez, R., Chawla, N. V., and Herrera, F. (2012). A unifying view on dataset shift in classification. *Pattern Recognition*, 45(1), 521-530. https://doi.org/10.1016/j.patcog.2011.06.019
19. Quiñonero-Candela, J., Sugiyama, M., Schwaighofer, A., and Lawrence, N. D., eds. (2009). *Dataset Shift in Machine Learning*. MIT Press.
20. Coles, S. (2001). *An Introduction to Statistical Modeling of Extreme Values*. Springer. https://doi.org/10.1007/978-1-4471-3675-0
21. Rousseeuw, P. J., and Leroy, A. M. (1987). *Robust Regression and Outlier Detection*. Wiley. https://doi.org/10.1002/0471725382
22. Cook, R. D. (1977). Detection of influential observation in linear regression. *Technometrics*, 19(1), 15-18. https://doi.org/10.1080/00401706.1977.10489493
23. Zimek, A., Schubert, E., and Kriegel, H.-P. (2012). A survey on unsupervised outlier detection in high-dimensional numerical data. *Statistical Analysis and Data Mining*, 5(5), 363-387. https://doi.org/10.1002/sam.11161
24. Chandola, V., Banerjee, A., and Kumar, V. (2012). Anomaly detection for discrete sequences: A survey. *IEEE Transactions on Knowledge and Data Engineering*, 24(5), 823-839. https://doi.org/10.1109/TKDE.2010.235
25. van der Aalst, W. M. P. (2016). *Process Mining: Data Science in Action* (2nd ed.). Springer. https://doi.org/10.1007/978-3-662-49851-4
26. Akoglu, L., Tong, H., and Koutra, D. (2015). Graph based anomaly detection and description: A survey. *Data Mining and Knowledge Discovery*, 29, 626-688. https://doi.org/10.1007/s10618-014-0365-y
27. Freeman, L. C. (1978). Centrality in social networks conceptual clarification. *Social Networks*, 1(3), 215-239. https://doi.org/10.1016/0378-8733(78)90021-7
28. Page, L., Brin, S., Motwani, R., and Winograd, T. (1999). *The PageRank Citation Ranking: Bringing Order to the Web*. Stanford InfoLab Technical Report 1999-66. http://ilpubs.stanford.edu:8090/422/
29. Ranshous, S., Shen, S., Koutra, D., Harenberg, S., Faloutsos, C., and Samatova, N. F. (2015). Anomaly detection in dynamic networks: A survey. *WIREs Computational Statistics*, 7(3), 223-247. https://doi.org/10.1002/wics.1347
30. Ma, X., Wu, J., Xue, S., Yang, J., Zhou, C., Sheng, Q. Z., Xiong, H., and Akoglu, L. (2023). A comprehensive survey on graph anomaly detection with deep learning. *IEEE Transactions on Knowledge and Data Engineering*, 35(12), 12012-12038. https://doi.org/10.1109/TKDE.2021.3118815
31. Shekhar, S., Lu, C.-T., and Zhang, P. (2003). A unified approach to detecting spatial outliers. *GeoInformatica*, 7, 139-166. https://doi.org/10.1023/A:1023455925009
32. Kou, Y., Lu, C.-T., and Chen, D. (2006). Spatial weighted outlier detection. In *Proceedings of the 2006 SIAM International Conference on Data Mining*, 614-618. https://doi.org/10.1137/1.9781611972764.71
33. Atluri, G., Karpatne, A., and Kumar, V. (2018). Spatio-temporal data mining: A survey of problems and methods. *ACM Computing Surveys*, 51(4), Article 83. https://doi.org/10.1145/3161602
34. Smets, K., and Vreeken, J. (2011). The odd one out: Identifying and characterising anomalies. In *Proceedings of the 2011 SIAM International Conference on Data Mining*, 804-815. https://doi.org/10.1137/1.9781611972818.69
35. Taha, A., and Hadi, A. S. (2019). Anomaly detection methods for categorical data: A review. *ACM Computing Surveys*, 52(2), Article 38. https://doi.org/10.1145/3312739
36. Gao, J., Fan, W., Turaga, D. S., Parthasarathy, S., and Han, J. (2011). A spectral framework for detecting inconsistency across multi-source object relationships. In *2011 IEEE 11th International Conference on Data Mining*, 1050-1055. https://doi.org/10.1109/ICDM.2011.82
37. Wang, S., Liu, J., Yu, G., Liu, X., Zhou, S., Zhu, E., Yang, Y., Yin, J., and Yang, W. (2024). Multiview deep anomaly detection: A systematic exploration. *IEEE Transactions on Neural Networks and Learning Systems*, 35(2), 1651-1665. https://doi.org/10.1109/TNNLS.2022.3184723
38. Hendrycks, D., and Gimpel, K. (2017). A baseline for detecting misclassified and out-of-distribution examples in neural networks. In *International Conference on Learning Representations*. https://arxiv.org/abs/1610.02136
39. Hendrycks, D., Mazeika, M., and Dietterich, T. (2019). Deep anomaly detection with outlier exposure. In *International Conference on Learning Representations*. https://arxiv.org/abs/1812.04606
40. Yang, J., Zhou, K., Li, Y., and Liu, Z. (2021). Generalized out-of-distribution detection: A survey. *arXiv preprint arXiv:2110.11334*. https://doi.org/10.48550/arXiv.2110.11334
41. Gneiting, T., and Raftery, A. E. (2007). Strictly proper scoring rules, prediction, and estimation. *Journal of the American Statistical Association*, 102(477), 359-378. https://doi.org/10.1198/016214506000001437
42. Rubin, D. B. (1976). Inference and missing data. *Biometrika*, 63(3), 581-592. https://doi.org/10.1093/biomet/63.3.581
43. Little, R. J. A., and Rubin, D. B. (2019). *Statistical Analysis with Missing Data* (3rd ed.). Wiley. https://doi.org/10.1002/9781119482260
44. Cochran, W. G. (1977). *Sampling Techniques* (3rd ed.). Wiley.
45. Dasu, T., and Johnson, T. (2003). *Exploratory Data Mining and Data Cleaning*. Wiley. https://doi.org/10.1002/0471448354
46. Rousseeuw, P. J., and van Zomeren, B. C. (1990). Unmasking multivariate outliers and leverage points. *Journal of the American Statistical Association*, 85(411), 633-639. https://doi.org/10.1080/01621459.1990.10474920
47. Chawla, N. V., and Gionis, A. (2013). k-means--: A unified approach to clustering and outlier detection. In *Proceedings of the 2013 SIAM International Conference on Data Mining*, 189-197. https://doi.org/10.1137/1.9781611972832.21
48. Lazarevic, A., and Kumar, V. (2005). Feature bagging for outlier detection. In *Proceedings of the Eleventh ACM SIGKDD International Conference on Knowledge Discovery in Data Mining*, 157-166. https://doi.org/10.1145/1081870.1081891
