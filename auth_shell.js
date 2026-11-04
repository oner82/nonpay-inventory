// 업무 이메일 확인과 직원 권한 승인을 분리한다. 기존 PIN과 사용자 문서는 읽지 않는다.
import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js';
import {
  initializeAuth, browserSessionPersistence, onAuthStateChanged, signInWithEmailAndPassword,
  createUserWithEmailAndPassword, sendEmailVerification, sendPasswordResetEmail, signOut
} from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js';

const element = id => document.getElementById(id);
const status = text => { element('status').textContent = text; };
const form = element('authForm');
let auth;
let busy = false;

function showUser(user) {
  form.hidden = Boolean(user);
  element('signedIn').hidden = !user;
  element('fields').disabled = busy;
  if (!user) return;
  element('address').textContent = user.email;
  element('verify').hidden = user.emailVerified;
  status(user.emailVerified
    ? '업무 이메일 확인이 완료되었습니다. 관리자가 기존 작성자 기록과 연결한 후 업무 화면을 열 수 있습니다. 현재 업무 앱은 보안 점검 중입니다.'
    : '업무 이메일 확인이 필요합니다. 메일의 링크를 열고 이 화면에서 인증 상태 확인을 눌러 주세요.');
}

function friendlyError(error) {
  const messages = {
    'auth/email-already-in-use': '계정 등록을 마칠 수 없습니다. 로그인 또는 비밀번호 재설정을 이용해 주세요.',
    'auth/invalid-email': '업무 이메일 주소를 확인해 주세요.',
    'auth/weak-password': '더 긴 새 비밀번호를 입력해 주세요.',
    'auth/password-does-not-meet-requirements': '새 비밀번호가 병원 계정 정책을 충족해야 합니다.',
    'auth/too-many-requests': '요청이 많습니다. 잠시 후 다시 시도해 주세요.',
    'auth/network-request-failed': '연결 상태를 확인하고 다시 시도해 주세요.'
  };
  return messages[error.code] || '처리할 수 없습니다. 입력한 이메일과 비밀번호를 확인해 주세요.';
}

async function perform(action) {
  if (busy || !auth) return;
  busy = true;
  element('fields').disabled = true;
  try { await action(); } catch (error) { status(friendlyError(error)); }
  finally { busy = false; element('fields').disabled = false; }
}

const email = () => element('email').value.trim();
const password = () => element('password').value;
form.addEventListener('submit', event => {
  event.preventDefault();
  perform(async () => {
    await signInWithEmailAndPassword(auth, email(), password());
    element('password').value = '';
  });
});
element('register').addEventListener('click', () => {
  if (!form.reportValidity()) return;
  if (password().length < 12) { status('새 계정에는 12자 이상의 비밀번호를 입력해 주세요.'); return; }
  perform(async () => {
    const { user } = await createUserWithEmailAndPassword(auth, email(), password());
    element('password').value = '';
    await sendEmailVerification(user);
    status('인증 메일을 보냈습니다. 메일 확인 후 인증 상태 확인을 눌러 주세요.');
  });
});
element('reset').addEventListener('click', () => {
  if (!element('email').reportValidity()) return;
  perform(async () => {
    await sendPasswordResetEmail(auth, email());
    status('등록된 이메일이면 비밀번호 재설정 안내를 받을 수 있습니다.');
  });
});
element('verify').addEventListener('click', () => perform(async () => {
  await sendEmailVerification(auth.currentUser);
  status('인증 메일을 다시 보냈습니다.');
}));
element('refresh').addEventListener('click', () => perform(async () => {
  await auth.currentUser.reload();
  await auth.currentUser.getIdToken(true);
  showUser(auth.currentUser);
}));
element('logout').addEventListener('click', () => perform(async () => {
  await signOut(auth);
  status('로그아웃했습니다.');
}));

try {
  sessionStorage.removeItem('orInventoryUser');
  localStorage.removeItem('orInventoryUser');
  const response = await fetch('/__/firebase/init.json', { cache:'no-store' });
  if (!response.ok) throw Error('config');
  const config = await response.json();
  if (config.projectId !== 'nonpay-inventory') throw Error('project');
  auth = initializeAuth(initializeApp(config), { persistence:browserSessionPersistence });
  auth.languageCode = 'ko';
  onAuthStateChanged(auth, user => {
    showUser(user);
    if (!user) status('기존 직원은 업무 이메일로 새 계정을 등록해 주세요.');
  });
} catch { status('직원 인증을 연결하지 못했습니다. 새로고침 후 다시 시도해 주세요.'); }
