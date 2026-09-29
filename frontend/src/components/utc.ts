import { createContext, useContext } from 'react';

/** Whether times render in UTC (true) or the browser's zone. Set in the masthead. */
export const UtcContext = createContext(false);
export const useUtc = () => useContext(UtcContext);
