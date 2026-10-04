import { run } from './cli.js';
import { removeInFlight, SIGNAL_EXIT } from './utils/inflight.js';

// A closed pipe (`pkinative ... | head`) is routine: end quietly with exit 0.
const onStreamError = (err: NodeJS.ErrnoException): void => {
    if (err.code === 'EPIPE') process.exit(0);
    throw err;
};
process.stdout.on('error', onStreamError);
process.stderr.on('error', onStreamError);

// Interrupted: remove the file being written (never a finished one), exit 128 + signal.
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.on(signal, () => {
        removeInFlight();
        process.exit(SIGNAL_EXIT[signal]);
    });
}

void run(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
});
