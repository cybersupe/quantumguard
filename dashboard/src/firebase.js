import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider, signInWithPopup, signOut } from "firebase/auth";
import { getFirestore, doc, getDoc, setDoc, updateDoc, increment, collection, query, where, getDocs } from "firebase/firestore";

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
export const logOut = () => signOut(app);

const FREE_SCAN_LIMIT = 10;

// Check if user can scan today
export const canUserScan = async (userId) => {
  if (!userId) return { allowed: true, remaining: 3 }; // guest gets 3
  try {
    const today = new Date().toISOString().split("T")[0];
    const userRef = doc(db, "users", userId);
    const userSnap = await getDoc(userRef);
    if (!userSnap.exists()) {
      await setDoc(userRef, { scansToday: 0, lastScanDate: today, totalScans: 0 });
      return { allowed: true, remaining: FREE_SCAN_LIMIT };
    }
    const data = userSnap.data();
    if (data.lastScanDate !== today) {
      await updateDoc(userRef, { scansToday: 0, lastScanDate: today });
      return { allowed: true, remaining: FREE_SCAN_LIMIT };
    }
    const remaining = FREE_SCAN_LIMIT - (data.scansToday || 0);
    return { allowed: remaining > 0, remaining: Math.max(0, remaining) };
  } catch (e) {
    console.error(e);
    return { allowed: true, remaining: FREE_SCAN_LIMIT };
  }
};

// Increment scan count after a scan
export const incrementScanCount = async (userId) => {
  if (!userId) return;
  try {
    const today = new Date().toISOString().split("T")[0];
    const userRef = doc(db, "users", userId);
    await updateDoc(userRef, {
      scansToday: increment(1),
      totalScans: increment(1),
      lastScanDate: today,
    });
  } catch (e) {
    console.error(e);
  }
};

// Get user profile stats
export const getUserProfile = async (userId) => {
  if (!userId) return null;
  try {
    const userRef = doc(db, "users", userId);
    const userSnap = await getDoc(userRef);
    const userData = userSnap.exists() ? userSnap.data() : {};

    const q = query(collection(db, "scans"), where("userId", "==", userId));
    const snapshot = await getDocs(q);
    const scans = snapshot.docs.map(d => d.data());

    const avgScore = scans.length > 0
      ? Math.round(scans.reduce((sum, s) => sum + (s.score || 0), 0) / scans.length)
      : 0;

    const totalFindings = scans.reduce((sum, s) => sum + (s.findings || 0), 0);

    return {
      totalScans: scans.length,
      avgScore,
      totalFindings,
      scansToday: userData.scansToday || 0,
      remainingToday: Math.max(0, FREE_SCAN_LIMIT - (userData.scansToday || 0)),
    };
  } catch (e) {
    console.error(e);
    return null;
  }
};