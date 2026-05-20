"""System-wide biometric and session constants."""

MINUTIAE_COUNT = 32
MIN_GENUINE_MINUTIAE = 8
MAX_AUTHORIZED_USERS = 5
EDIT_WINDOW_SECONDS = 300  # 5 minutes
BIOMETRIC_MATCH_RATIO = 0.70
# Minimum score gap between top two candidates to accept identification
BIOMETRIC_AMBIGUITY_GAP = 0.05
# Stricter gates for decrypt — both hash and spatial must pass (not only max-of-two)
BIOMETRIC_DECRYPT_MIN_HASH = 0.62
BIOMETRIC_DECRYPT_MIN_SPATIAL = 0.58
BIOMETRIC_DECRYPT_MIN_CIPHER = 0.55
MINUTIAE_SPATIAL_TOLERANCE = 12.0
