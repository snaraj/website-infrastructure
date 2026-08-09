import { mount } from 'svelte';
import App from './App.svelte';
import './styles.css';

const target = document.getElementById('app');

if (!target) {
  throw new Error('application mount point is missing');
}

target.replaceChildren();
mount(App, { target });
