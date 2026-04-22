import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider, signInWithPopup, signOut } from "firebase/auth";
import { getFirestore, doc, getDoc, setDoc, updateDoc, increment } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyDPAkvvr2d3r1Q1X-d_66mATWuM-odC_uc",
  authDomain: "quantumguard-1deb6.firebaseapp.com",
  projectId: "quantumguard-1deb6",
  storageBucket: "quantumguard-1deb6.firebasestorage.app",
  messagingSenderId: "935526339089",
  appId: "1:935526339089:web:52d19bb016cca3dd5757b0"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
export const googleProvider = new GoogleAuthProvider();

export const signInWithGoogle = () => signInWithPopup(auth, googleProvider);
export const logOut = () => signOut(auth);

export const canUserScan = async (userId) => {
  if (!userId) return { allowed: true };
  try {
    const ref = doc(db, "users", userId);
    const snap = await getDoc(ref);
    if (!snap.exists()) return { allowed: true };
    const data = snap.data();
    const today = new Date().toDateString();
    if (data.lastScanDate !== today) return { allowed: true };
    return { allowed: (data.scansToday || 0) < 10 };
  } catch { return { allowed: true }; }
};

export const incrementScanCount = async (userId) => {
  if (!userId) return;
  try {
    const ref = doc(db, "users", userId);
    const today = new Date().toDateString();
    const snap = await getDoc(ref);
    if (!snap.exists() || snap.data().lastScanDate !== today) {
      await setDoc(ref, { scansToday: 1, lastScanDate: today }, { merge: true });
    } else {
      await updateDoc(ref, { scansToday: increment(1) });
    }
  } catch (e) { console.error(e); }
};

export const getUserProfile = async (userId) => {
  if (!userId) return null;
  try {
    const scansRef = doc(db, "users", userId);
    const snap = await getDoc(scansRef);
    const data = snap.exists() ? snap.data() : {};
    const today = new Date().toDateString();
    const scansToday = data.lastScanDate === today ? (data.scansToday || 0) : 0;
    return {
      totalScans: data.totalScans || 0,
      avgScore: data.avgScore || 0,
      totalFindings: data.totalFindings || 0,
      scansToday,
      remainingToday: Math.max(0, 10 - scansToday),
    };
  } catch { return { totalScans: 0, avgScore: 0, totalFindings: 0, scansToday: 0, remainingToday: 10 }; }
};