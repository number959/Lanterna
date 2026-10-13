import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
// Scale Radix Colors per i colori di stato (verde, indaco, ambra, rosso): prima le chiare, poi le scure
// (selettore .dark), così con la classe "dark" su <html> vincono le scure.
import '@radix-ui/colors/green.css';
import '@radix-ui/colors/green-alpha.css';
import '@radix-ui/colors/indigo.css';
import '@radix-ui/colors/indigo-alpha.css';
import '@radix-ui/colors/amber.css';
import '@radix-ui/colors/amber-alpha.css';
import '@radix-ui/colors/red.css';
import '@radix-ui/colors/red-alpha.css';
import '@radix-ui/colors/green-dark.css';
import '@radix-ui/colors/green-dark-alpha.css';
import '@radix-ui/colors/indigo-dark.css';
import '@radix-ui/colors/indigo-dark-alpha.css';
import '@radix-ui/colors/amber-dark.css';
import '@radix-ui/colors/amber-dark-alpha.css';
import '@radix-ui/colors/red-dark.css';
import '@radix-ui/colors/red-dark-alpha.css';
import './fonts.css';
import './styles.css';
import App from './App';
import { initFx } from './fx';
import { apply, effective, readPref } from './theme';

// Il tema si applica prima del primo disegno, per evitare il lampo del tema sbagliato.
apply(effective(readPref()));
initFx();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
