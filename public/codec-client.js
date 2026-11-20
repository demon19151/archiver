let worker;
let nextId = 0;
const pending = new Map();

function rejectPending(error) {
  for (const task of pending.values()) task.reject(error);
  pending.clear();
  worker?.terminate();
  worker = null;
}

export function runCodec(operation, buffer) {
  if (!worker) {
    try {
      worker = new Worker(new URL('./codec-worker.bundle.js', import.meta.url));
      worker.onmessage = ({ data }) => {
        const task = pending.get(data.id);
        if (!task) return;
        pending.delete(data.id);
        if (data.error) task.reject(new Error(data.error.message));
        else task.resolve(data);
      };
      worker.onerror = event => {
        event.preventDefault();
        rejectPending(new Error('Не удалось запустить обработчик файлов. Обновите страницу и повторите попытку.'));
      };
      worker.onmessageerror = () => rejectPending(new Error('Ошибка обмена данными с обработчиком файлов'));
    } catch (error) {
      return Promise.reject(error);
    }
  }
  return new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    try {
      worker.postMessage({ id, operation, buffer }, [buffer]);
    } catch (error) {
      pending.delete(id);
      reject(error);
    }
  });
}
