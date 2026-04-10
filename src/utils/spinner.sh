#!/usr/bin/env bash
# TRAKTR Spinner & Progress v2.0
# Animated progress spinner, tool command display, and step progress bar
# Usage: source spinner.sh (sourced by traktr.sh or phase scripts)

# ── Color / style codes ────────────────────────────────────────────────────
_SP_CYN='\033[1;36m'    # spinner character
_SP_GRN='\033[1;32m'    # tool name
_SP_YEL='\033[1;33m'    # elapsed time
_SP_DIM='\033[2m'       # dim/gray for commands
_SP_MAG='\033[1;35m'    # progress bar accent
_SP_WHT='\033[1;37m'    # bright white labels
_SP_RST='\033[0m'       # reset
_SP_HIDE='\033[?25l'    # hide cursor
_SP_SHOW='\033[?25h'    # show cursor
_SP_ERASE='\033[2K'     # erase current line
_SP_CR='\r'             # carriage return

# ── Braille animation frames ───────────────────────────────────────────────
_SPINNER_FRAMES=(
  "\xe2\xa0\x8b"   # ⠋
  "\xe2\xa0\x99"   # ⠙
  "\xe2\xa0\xb9"   # ⠹
  "\xe2\xa0\xb8"   # ⠸
  "\xe2\xa0\xbc"   # ⠼
  "\xe2\xa0\xb4"   # ⠴
  "\xe2\xa0\xa6"   # ⠦
  "\xe2\xa0\xa7"   # ⠧
  "\xe2\xa0\x87"   # ⠇
  "\xe2\xa0\x8f"   # ⠏
)

# ── Internal state ──────────────────────────────────────────────────────────
_SPINNER_PID=""
_SPINNER_MSG=""
_SPINNER_MSG_FILE=""
_SPINNER_START_TS=""

# ═══════════════════════════════════════════════════════════════════════════
#  _spinner_start "message"
#  Starts an animated spinner in the background.
# ═══════════════════════════════════════════════════════════════════════════
_spinner_start() {
  local msg="${1:-Working...}"

  # Stop any existing spinner first
  [[ -n "$_SPINNER_PID" ]] && _spinner_stop 2>/dev/null

  _SPINNER_START_TS=$(date +%s)
  _SPINNER_MSG_FILE=$(mktemp /tmp/.traktr_spinner_msg.XXXXXX)
  echo "$msg" > "$_SPINNER_MSG_FILE"

  # Hide cursor while spinner is active
  printf '%b' "$_SP_HIDE" >&2

  # Launch the animation loop in a background subshell
  (
    local i=0
    local frame_count=${#_SPINNER_FRAMES[@]}

    while true; do
      local frame="${_SPINNER_FRAMES[$((i % frame_count))]}"
      local now elapsed_s mins secs elapsed_fmt current_msg

      now=$(date +%s)
      elapsed_s=$(( now - _SPINNER_START_TS ))
      mins=$(( elapsed_s / 60 ))
      secs=$(( elapsed_s % 60 ))
      elapsed_fmt=$(printf '%02d:%02d' "$mins" "$secs")

      # Read the latest message from the shared file
      current_msg="Working..."
      [[ -f "$_SPINNER_MSG_FILE" ]] && current_msg=$(cat "$_SPINNER_MSG_FILE" 2>/dev/null)

      printf '%b' "${_SP_ERASE}${_SP_CR}  ${_SP_CYN}${frame}${_SP_RST} ${_SP_YEL}[${elapsed_fmt}]${_SP_RST} ${current_msg}" >&2

      i=$(( i + 1 ))
      sleep 0.08
    done
  ) &

  _SPINNER_PID=$!
  disown "$_SPINNER_PID" 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════════════════
#  _spinner_update "new message"
#  Updates the spinner message without restarting it.
# ═══════════════════════════════════════════════════════════════════════════
_spinner_update() {
  local msg="${1:-Working...}"
  if [[ -n "$_SPINNER_MSG_FILE" && -f "$_SPINNER_MSG_FILE" ]]; then
    echo "$msg" > "$_SPINNER_MSG_FILE"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════
#  _spinner_stop
#  Stops the background spinner and restores the cursor.
# ═══════════════════════════════════════════════════════════════════════════
_spinner_stop() {
  if [[ -n "$_SPINNER_PID" ]]; then
    kill "$_SPINNER_PID" 2>/dev/null
    wait "$_SPINNER_PID" 2>/dev/null
    _SPINNER_PID=""
  fi

  # Clean up the message file
  if [[ -n "$_SPINNER_MSG_FILE" && -f "$_SPINNER_MSG_FILE" ]]; then
    rm -f "$_SPINNER_MSG_FILE"
    _SPINNER_MSG_FILE=""
  fi

  # Clear the spinner line and restore the cursor
  printf '%b' "${_SP_ERASE}${_SP_CR}${_SP_SHOW}" >&2
}

# ═══════════════════════════════════════════════════════════════════════════
#  _show_tool_cmd "tool_name" "full command"
#  Prints the tool launch line in a styled format.
#    ▸ katana -u http://target -jc -d 5 -js-crawl
# ═══════════════════════════════════════════════════════════════════════════
_show_tool_cmd() {
  local tool="${1:-tool}" cmd="${2:-}"

  # Extract the arguments portion (everything after the binary name)
  local args=""
  if [[ -n "$cmd" ]]; then
    # Strip leading whitespace, then remove the first word (binary name)
    args="${cmd#"${cmd%%[! ]*}"}"          # trim leading spaces
    args="${args#* }"                       # drop first word (the binary)
    # If cmd was just the tool name with no args, show the full cmd
    [[ "$args" == "$cmd" ]] && args=""
  fi

  if [[ -n "$args" ]]; then
    printf '%b\n' "  ${_SP_WHT}\xe2\x96\xb8${_SP_RST} ${_SP_GRN}${tool}${_SP_RST} ${_SP_DIM}${args}${_SP_RST}" >&2
  else
    printf '%b\n' "  ${_SP_WHT}\xe2\x96\xb8${_SP_RST} ${_SP_GRN}${tool}${_SP_RST}" >&2
  fi
}

# ═══════════════════════════════════════════════════════════════════════════
#  _progress_bar <current_step> <total_steps> "Step label"
#  Renders a visual progress bar for multi-step operations.
#    ━━━━━━━━━━━━━━━━━━━━ Step 2/6: Deep Crawl
# ═══════════════════════════════════════════════════════════════════════════
_progress_bar() {
  local current="${1:-1}" total="${2:-1}" label="${3:-}"
  local bar_width=20

  # Clamp values
  (( current < 0 )) && current=0
  (( current > total )) && current=$total

  # Calculate filled vs empty segments
  local filled=$(( (current * bar_width) / total ))
  local empty=$(( bar_width - filled ))

  # Build the bar string using heavy horizontal line (━)
  local bar_filled="" bar_empty=""
  local i
  for (( i = 0; i < filled; i++ )); do
    bar_filled+="\xe2\x94\x81"   # ━
  done
  for (( i = 0; i < empty; i++ )); do
    bar_empty+="\xe2\x94\x81"    # ━
  done

  local step_info="Step ${current}/${total}"
  [[ -n "$label" ]] && step_info="${step_info}: ${label}"

  printf '%b\n' "  ${_SP_MAG}${bar_filled}${_SP_RST}${_SP_DIM}${bar_empty}${_SP_RST} ${_SP_WHT}${step_info}${_SP_RST}" >&2
}

# ═══════════════════════════════════════════════════════════════════════════
#  Cleanup trap -- ensure spinner is stopped and cursor is restored if the
#  parent script exits unexpectedly.
# ═══════════════════════════════════════════════════════════════════════════
_spinner_cleanup() {
  [[ -n "$_SPINNER_PID" ]] && kill "$_SPINNER_PID" 2>/dev/null
  [[ -n "$_SPINNER_MSG_FILE" && -f "$_SPINNER_MSG_FILE" ]] && rm -f "$_SPINNER_MSG_FILE"
  printf '%b' "${_SP_SHOW}" >&2
}

# Register cleanup -- append to existing EXIT traps rather than overwriting
trap '_spinner_cleanup' EXIT
