import { mount } from 'svelte';
import App from './App.svelte';
import './styles.css';

// Failing loudly when the static shell is malformed prevents a half-mounted
// page from looking healthy during a release verification.
const target = document.getElementById('app');

if (!target) {
  throw new Error('application mount point is missing');
}

target.replaceChildren();
mount(App, { target });
