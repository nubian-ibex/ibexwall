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
    width: 44px;
    height: var(--target);
    border: none;
    border-radius: 999px;
    background: var(--border-strong);
    position: relative;
    cursor: pointer;
    padding: 0;
    flex: none;
    align-self: center;
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
    top: 5px;
    left: 5px;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: var(--surface);
    transition: left 0.15s ease;
  }
  button[aria-checked='true'] .knob {
    left: 24px;
  }
</style>
