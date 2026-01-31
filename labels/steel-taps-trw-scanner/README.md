# Host Scanner Labels using TRW and TAPS

## Description
This folder contains a new set of host-level scanner labels generated using TRW (Threshold Random Walk) and TAPS (Time based Access Pattern Sequential hypothesis testing). These labels are analyzed using FRGP DDoS Dataset 2020, provided by the USC/CLASSNET project (https://ant.isi.edu/classnet).

## Methodology

### Approach
TRW and TAPS are both based on statistical hypothesis testing, which defines two hypotheses:
- H0: host is benign
- H1: host is scanner

The final output for each host can be ```scanner```, ```benign```, or ```can't say```.

### Observations
We observe successful and failed connections and accumulate them to calculate the likelihood ratio, which is the indicator of whether the host is benign or scanner.
<!-- 
#### TRW


#### TAPS -->

### Model Parameters
#### Theta values
These are model parameters for calculating the likelihood ratio:
- θ₀: Probability of a successful connection if the source is benign
- θ₁: Probability of a successful connection if the source is scanner

In this data, we choose θ₀ as 0.95, indicating that a benign host is 95% likely to generate a successful connection.

#### Threshold values
Thresholds are calculated based on desired true positive (β), and desired false positive (α). In this data, α is set to 0.01 and β is set to 0.99.

### Final Decision
The final host label is determined by comparing the
log likelihood ratio (LLR) to the upper threshold and lower threshold:
- If LLR exceeds the upper threshold, the host is ```scanner```
- If LLR falls below the lower threshold, the host is ```benign```
- Otherwise, the host is ```can't say```

## Result
The table below describes the number of scanners identified by TRW and TAPS in each month data:
|  | May | Aug | Sep |
|:-----:|:-----:|:-----:|:-----:|
| TRW-identified scanners| 8036 | 6267 | 6717 |
| TAPS-identified scanners | 547 | 563 | 530 |



## Label Format
The labels are provided as txt files and it contains a list of scanner hosts' IP addresses. Each month has TRW and TAPS-identified scanners, respectively.

