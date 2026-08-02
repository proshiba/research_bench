// 参照先が選ばれていない関係の検出。判定はポータルと同じものを使う。
//
// 実装は assets/js/index-health.js にある。集める側とポータルで別々に持つと、
// 片方だけ直したときに画面と手元のデータが食い違う。util.js を共有しているのと
// 同じ向き（tools → assets）で参照する。

export { brokenRelNote, brokenRels, markBrokenRefs } from "../../../assets/js/index-health.js";
