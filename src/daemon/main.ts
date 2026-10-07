import { createDaemon } from './server.ts';

const port = Number(process.env.LAUNCHPROOF_PORT ?? process.argv.find((a) => a.startsWith('--port='))?.slice(7) ?? 0) || 0;

const { port: bound } = await createDaemon({ port });
process.stdout.write(`launchproof daemon listening on 127.0.0.1:${bound}\n`);

const shutdown = (): void => {
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
