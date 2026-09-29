import { Component, type ReactNode } from 'react';
import { Button, Empty } from './ui';

/** Catches a render error in one screen so the masthead and the other screens keep working. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="flex-1 flex items-center justify-center">
        <Empty title="This screen failed to render.">
          {this.state.error.message}
          <span className="block mt-3">
            <Button onClick={() => window.location.reload()}>Reload</Button>
          </span>
        </Empty>
      </div>
    );
  }
}
