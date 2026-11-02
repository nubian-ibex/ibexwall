<script lang="ts">
  // A switch is a switch: real role, keyboard operable, labelled.
  let {
    checked,
    label,
    disabled = false,
    onchange,
  }: {
    checked: boolean;
    label: string;
    disabled?: boolean;
    onchange?: (value: boolean) => void;
  } = $props();
</script>

<button
  type="button"
  role="switch"
  aria-checked={checked}
  aria-label={label}
  {disabled}
  onclick={() => onchange?.(!checked)}
>
  <span class="knob"></span>
</button>

<style>
  button {
    width: 48px;
    height: 28px;
    border: none;
    border-radius: 999px;
    background: var(--border-strong);
    position: relative;
    cursor: pointer;
    padding: 0;
    flex: none;
    align-self: center;
  }
  /* Keeps the 44px minimum touch target around the 28px visual track. */
  button::before {
    content: '';
    position: absolute;
    inset: -8px -2px;
  }
  button[aria-checked='true'] {
    background: var(--primary);
  }
  button:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .knob {
    position: absolute;
    top: 4px;
    left: 4px;
    width: 20px;
    height: 20px;
    border-radius: 50%;
    background: var(--surface);
    transition: left 0.15s ease;
  }
  button[aria-checked='true'] .knob {
    left: 24px;
  }
</style>
