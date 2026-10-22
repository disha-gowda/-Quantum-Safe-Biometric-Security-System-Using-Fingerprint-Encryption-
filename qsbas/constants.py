"""System-wide biometric and session constants."""

MINUTIAE_COUNT = 32
FACE_LANDMARK_COUNT = 32
MIN_GENUINE_MINUTIAE = 8
MAX_AUTHORIZED_USERS = 5
EDIT_WINDOW_SECONDS = 300  # 5 minutes
BIOMETRIC_MATCH_RATIO = 0.70
# Display / decision thresholds (percent = value * 100)
FINGERPRINT_VERIFY_THRESHOLD = 0.75
FACE_VERIFY_THRESHOLD = 0.80
# Independent face-texture floor so landmark geometry alone cannot pass a wrong face
FACE_EMBED_MIN = 0.78
# Minimum score gap between top two candidates to accept identification
BIOMETRIC_AMBIGUITY_GAP = 0.05
# Stricter gates for decrypt — both hash and spatial must pass (not only max-of-two)
BIOMETRIC_DECRYPT_MIN_HASH = 0.62
BIOMETRIC_DECRYPT_MIN_SPATIAL = 0.58
BIOMETRIC_DECRYPT_MIN_CIPHER = 0.55
MINUTIAE_SPATIAL_TOLERANCE = 12.0
FACE_LANDMARK_TOLERANCE = 0.09
MAX_DOCUMENT_BYTES = 12 * 1024 * 1024

# QSBAC-SPN v3: deep diffusion, chaotic injection, GF mix, entropy reinforcement
QSBAC_ENGINE_VERSION = 3
QSBAC_SPN_ROUNDS = 16
QSBAC_IV_BYTES = 16
