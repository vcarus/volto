//! The `bbr` congestion controller: a window of at most 1.25 times the
//! bandwidth-delay product it measures, plus what the path's own loss takes
//! out of it.
//!
//! It is the default (D108). The type is [`Bbr`].
//!
//! quinn-proto 0.11's BBR estimates the bottleneck bandwidth several times too
//! high, so its window never limits in-flight data, and a bulk download loses
//! what the bottleneck queue cannot hold. This controller uses no part of
//! quinn's BBR. It measures its own delivery rate and minimum RTT, and its
//! window is computed from them alone (D108).
//!
//! The window is a gain times the delivery rate measured once per round trip
//! (see `DeliveryRate`) times the minimum RTT. The gain is 1.25 unless the
//! path's loss has lowered it, as described below. Outside a recovery and a
//! probe the window is never below the initial window, 240 kB: 200 packets of
//! 1200 bytes, the default initial window of the BBR in quinn-proto 0.11
//! (`quinn::congestion::BbrConfig`). So on a path whose bandwidth-delay product is under 192 kB,
//! the window can be 240 kB. Until there is a delivery-rate sample and a
//! minimum RTT, the window is the initial window.
//!
//! quinn paces from the window (quinn-proto `src/connection/pacing.rs`,
//! `Pacer::delay`, which adds 1.25 windows of tokens per smoothed RTT), so the
//! window also sets the pacing rate. In-flight data sits at the window, and at
//! 1.25 a quarter of a bandwidth-delay product stands in the bottleneck queue
//! when the queue can hold it. 1.25 is
//! the highest pacing gain of BBR's ProbeBW cycle. BBR's window gain of two is a
//! ceiling above a sender that paces at the estimated rate. In quinn the window
//! is what the sender sends, so a gain of two keeps a whole bandwidth-delay
//! product queued and loses packets wherever the queue is shorter than that.
//!
//! The gain follows the path between 1.05 and 1.25. With the window at a gain
//! g, in-flight data is g times what the path carries in transit, and what the
//! bottleneck queue cannot hold of the rest is lost. In the lab a queue of
//! 0.04 bandwidth-delay products lost 19 percent of the packets at 1.25 and
//! 0.9 percent at 1.05. A path that loses packets at random needs the higher gain:
//! with 2 percent of them lost, a fixed 1.05 carried a third of what 1.25
//! carried, because each loss holds in-flight data for a round trip and at
//! 1.05 the window has no room to bring the delivery rate back. The two kinds
//! of loss differ in one thing the sender can see. A lower gain removes the
//! loss of a queue and leaves random loss as it is. The rule below is ours.
//!
//! The controller counts the bytes acknowledged and the bytes lost over loss
//! windows of at least four sample intervals and 2000 packets. The loss share
//! of a window is its loss above the path's base loss, described below: the
//! base loss times the window's bytes is taken off its lost bytes, not below
//! zero. Loss at the base loss is not the queue's, and a lower gain does not
//! remove it. When the last four windows at the present gain each lost
//! something and the mean of their loss shares is one percent or more, a trial
//! of a lower gain starts: the gain times the share delivered, which is the
//! in-flight data the path carried, and never under the floor. Windows that
//! lost so much that the path carried under 0.9 bandwidth-delay products start
//! no trial, because a queue loses at most what the window holds above one. If
//! the loss was the queue's, the loss at the lower gain is the part of the same
//! in-flight data that the lower window still exceeds, often none.
//!
//! The first two windows of a trial are left out. The lower gain is kept when
//! each of the next four lost less than the lowest of the four before the
//! trial, and their mean is at or under the middle between the loss before and
//! that prediction. The first of them that does not lose less ends the trial:
//! the old gain returns, and the wait before the next trial doubles, from 16
//! windows up to 256. This is a rank test. Eight windows whose loss does not
//! depend on the gain come in any order with the same chance, and the four
//! after the change are all below the four before it in 1 of 70 orders. The
//! chance here is higher than that, because a trial starts only after four
//! windows that all lost something, and windows without loss pass: loss series
//! recorded in the lab at a fixed gain passed in 2 to 3 of 100 places. Through
//! 1.8.0 one window of eight at or under the middle kept the gain, and after a
//! burst of loss the next window is at or under it at any gain. On a path with
//! loss in bursts every trial was kept, the gain stayed near the floor, and the
//! path carried 4 to 5 percent less than at 1.25. Under random loss a trial
//! lowers the gain by the loss share, 1.25 to 1.225 at 2 percent.
//!
//! A lowered gain is tried one step of 0.05 higher after 16 windows. The
//! middle alone judges it, in one window: when the loss is at or past the middle
//! between the loss before and the loss predicted for the higher gain, the
//! queue is still that short, the lowered gain returns and the wait doubles.
//! A gain that has come down after a loss burst or on a path that has changed
//! goes back up this way.
//!
//! A lowered gain is given up for 1.25 when the bandwidth estimate falls
//! under three quarters of the highest one since the gain was last 1.25. The
//! wait before the next trial of a lower gain doubles as after a refusal, and
//! that trial does not go as low as the gain given up: the floor is 0.05 above
//! it, and comes down by 0.05 every 256 windows. This guards a path with a
//! short queue and random loss, where a low gain passes the loss test and then
//! does not hold the rate.
//!
//! A window in which more than half of the intervals were app-limited did not
//! fill the queue. It counts for lowering the gain, because behind a short
//! queue the retransmissions stall the sender on flow control in nearly half
//! of all intervals. It does not count towards the 16 windows, and it can
//! refuse a higher gain on trial and cannot keep one. Otherwise a stream that
//! sends less than the path carries would take a lowered gain back to 1.25
//! step by step, and the next download would lose to the queue again.
//!
//! A connection that sends too little for a loss window within 32 intervals
//! has its trial dropped and its gain set back to 1.25, and the gain starts
//! again when the startup gain returns. Probe intervals and the two intervals
//! after a probe or a change of gain are left out of the loss windows, and so
//! are the interval that ends a startup and the seven after it. A startup ends
//! with more in flight than the path holds, and that loss is not the steady
//! gain's.
//!
//! A path can drop a share of all packets whatever the sender sends: its base
//! loss. quinn takes an acknowledged packet out of in-flight data one round
//! trip after it was sent, and a lost one only when it declares it lost, 1.25
//! round trips after it was sent (`LOSS_TIME_THRESHOLD` below,
//! D116). With a base loss p, a window of 1.25 times
//! the bandwidth-delay product therefore delivers 1.25 (1 - p) / (1 + 0.25 p)
//! times the estimate. Above about one sixth lost that is under one, each
//! sample is lower than the estimate, and the window falls to its floor
//! however much the path carries. In the lab, on a path that carried 115
//! Mbit/s with 23 percent lost, each of three releases sent 21 to 22 Mbit/s
//! and delivered 16 to 17.
//!
//! So outside the startup and a probe the window is multiplied by
//! (1 + t p) / (1 - p), where t is the time threshold minus one and p is the
//! base loss, at most 40 percent. The rule is ours.
//!
//! Loss the sender causes by sending above a rate limit or a queue is not base
//! loss, and the window does not cover it. A window that grew with that loss
//! would grow without end at a limiter, because what it adds is lost and
//! covered again. So the base loss is read only where the sender's rate cannot
//! cause it: during a probe, whose window is half the estimated
//! bandwidth-delay product. Behind a buffer of under ten packets the probe's
//! own sending causes loss too, because quinn's pacer sends at least ten
//! packets at once and those bursts overflow such a buffer at any rate; in
//! `line_sim` behind a 20 Mbit/s queue of 10 kB the sent rate rose from 20.4 to
//! 23.5 Mbit/s for 19.4 delivered. This is a known limit. The startup is no
//! such place. It sends above the path by design, and in `line_sim` each of
//! three ways of reading the base loss from it read the sender's own loss
//! behind some limit. A reading counts the bytes acknowledged and the bytes
//! lost of the packets sent from the moment in-flight data has fallen to the
//! probe window until the probe ends. quinn reports a loss detection pass as
//! one congestion event with the send time of the newest packet it found lost,
//! so a pass counts whole when that packet was sent in the span. The reading
//! closes two smoothed RTTs after the probe ended. A probe that lost 75 percent
//! or more of its packets fell mostly into an outage and is dropped. A reading
//! needs 100 packets, and a probe that counted fewer is not dropped: its bytes
//! are carried into the next probe's, and the reading completes at the probe
//! where the sum reaches 100 packets. A probe at half the window counts about
//! the estimate times 200 ms or one smoothed RTT, whichever is longer, over 2
//! (1 + p / 4), so a sender at the 240 kB floor on an RTT of 200 ms or more
//! counts under 100 packets in one probe: in `line_sim` 45 to 62 at 200 and 250
//! ms with 30 and 40 percent lost. A completed reading of 75 percent or more is
//! dropped too. A reading between the bound of 40 percent and 75 percent is
//! kept, and the base loss is held at the bound where it is used. A partial
//! outage in the only reading can still raise the base loss until the next
//! probe. The fourth probe in a row that completes no kept reading clears the
//! kept readings and the carried bytes, and the base loss is zero until a new
//! reading. On a path where four probes together count under 100 packets, a
//! base loss once read would otherwise last for the whole connection. A probe
//! during a change of path can read too much loss, because quinn does not call
//! `Controller::on_ack` while it validates a new path (quinn-proto
//! `src/connection/mod.rs`, `Connection::on_packet_acked`) and still reports
//! the losses. This is a known limit. On the production limiter's evening
//! captures a window of 200 ms read 10 percent or more in 6 to 24 percent of
//! the cases and 25 percent or more in 1 to 3 percent, so a probe there can
//! read an episode's loss; this tail is accepted, at a mean cost of about 1
//! percent of the bytes sent on that line's shape. The base loss is the lowest
//! of the last four readings. Loss that comes in episodes is missing from some
//! probes, and loss that is steady shows in all of them. A single reading acts.
//! On a limiter line with loss in episodes calibrated to production captures,
//! waiting for a second reading did not lower sent over delivered in `line_sim`
//! (1.28 either way) and cost 9 to 14 percent of a 5 s transfer on a lossy
//! path, so it is not done. The first reading can therefore be an episode's or
//! an outage's. So a reading that brings the base loss from zero to 5 percent
//! or more acts at once and is confirmed: a further probe is due ten sample
//! intervals later, the estimate's window, and its reading enters the lowest of
//! four like any other, or clears the base loss by the rule of the next
//! paragraph. This happens each time a reading takes the base loss up from
//! zero, so again after a clearing. A reading taken in an outage or an episode
//! then acts until that probe has closed, about thirteen round trips, not
//! until the next regular probe 10 s or more later.
//! In `line_sim` the review's sweep of partial outages inside the early probe
//! behind clean policers had 68 of 144 runs more than 0.3 above 1.8.2's sent
//! over delivered over the first 12 s without the confirming probe and 1 with
//! it. It costs one probe and the lower of two readings: 5 to 6 percent of a 5
//! s transfer at 85 ms with 15 and 23 percent dropped, and 0.5 to 3 s more to
//! the full window at 151 to 250 ms. The base loss is to loss what the minimum
//! RTT is to delay. A rise in the path's loss therefore takes effect once every
//! kept reading has risen, which is up to four probes. The lag is a known
//! property. On the one production path it was measured on, the base loss moved
//! over hours. The rules of this paragraph are ours.
//!
//! A probe is under the path's rate only if half the estimate is, and right
//! after a startup behind a policer with a large burst allowance it is not:
//! the allowance lets the startup measure several times the token rate. So a
//! reading verifies its own premise. On a path that delivers 1 - p of what is
//! sent up to a limit, sending less makes less arrive only under the limit.
//! The reading compares the arrival rate of the packets sent while the probe
//! held its window with the arrival rate of the packets sent in the round trip
//! before the probe was entered, counted the same way by send time over the
//! minimum RTT before entry. The minimum RTT is the highest of three low
//! arrivals within a second, so a single round trip can be shorter than it by
//! up to the spread of those arrivals, and a packet of that round trip that
//! was acknowledged before entry is missed. That lowers the arrival rate before
//! entry by the share missed and raises the ratio; in `line_sim` the share
//! missed at entry was 0.000 in all 1403 entries. The reading is kept only when
//! the probe's arrival rate is at most 0.75 of the one before it. In `line_sim`
//! a probe under the path's rate gave 0.12 to 0.73 on every path with base
//! loss, and up to 0.90 behind clean limits, where a reading reads zero and
//! rejecting it costs nothing while no base loss is in force. The early probe
//! behind clean policers with burst allowances of 1 to 8 MB gave 1.10 to 1.40;
//! without the rule it read 0.23 to 0.64 of the sender's own loss. A reading
//! that fails is judged by what was sent in the two spans, acknowledged and
//! lost, counted the same way. When the probe did not lower the sending to 0.75
//! of the round trip before it either, as when a client holds the sender, it
//! says nothing about the path: it is unverified, dropped, not carried, and
//! does not count as a probe without a reading. When it did lower the sending
//! and the arrivals stayed, the sender was above the path's rate even at the
//! probe's, and a base loss in force is what put it there or keeps it there:
//! the kept readings and the carry are cleared, and the base loss is zero until
//! a new reading. That inference is too strong in two cases, which a second
//! review found in `line_sim`, and in both a base loss that was right is
//! cleared and the transfer runs as it did through 1.8.2 until the next kept
//! reading. First, a lossy path behind a policer whose burst allowance is half
//! a second to two seconds of its rate: when the factor comes into force the
//! estimate grows on the allowance to two or three times the token rate, the
//! confirming probe falls there, and it is above the limit. In a sweep of 96
//! such runs 16 cleared, and on one line (30 Mbit/s, 100 ms, a fifth dropped)
//! the base loss was zero for 74 of 90 s: 18.8 Mbit/s delivered, against 23 to
//! 24 without the clearing or without the confirming probe, and 14.7 for
//! 1.8.2. Second, an episode or a partial outage in the round trip before a
//! probe: the arrivals before the probe are low while lost bytes count as
//! sent, so the arrival ratio is high and the sending ratio low. 14 of 48 runs
//! with episodes behind a queue cleared once, and over 144 lossy lines the sum
//! delivered was 1.6 percent under that without the clearing. On no lossy line
//! did the controller deliver less than 1.8.2 does. The two rules are kept for
//! what they prevent at a limit: of the outage sweep above, 68 runs without
//! the confirming probe, 26 without the clearing, 1 with both. Both outcomes
//! end the early probe's repeat, because arrivals that did not fall mean that
//! the startup's loss was a limit's. A probe whose rate stays above a limit
//! while the allowance that fed the arrivals before it runs out inside it could
//! pass; `line_sim` did not reproduce that case. The rule is ours.
//!
//! The first probe would come when the minimum RTT expires, 10 s after it was
//! last taken, and in production it came 14 to 45 s after the start. So when a
//! startup ends having lost 5 percent or more of its bytes, and no reading is
//! kept, the minimum RTT's lifetime is treated as over, and the probe starts at
//! the next ACK that does not find the sender app-limited. Nothing else about
//! the probe changes. After a startup that lost that much, the path either
//! drops a share of everything or the startup overshot a limit, and only a
//! reading below the path's rate tells the two apart. Under 5 percent the
//! factor is under 1.07, and waiting costs little. While no reading is kept
//! after such a startup, a probe whose reading closes short makes the next one
//! due at once, provided it counted at least 25 packets, a quarter of a
//! reading, and the bytes carried so far, its own included, lost 5 percent or
//! more. Four such probes complete a reading, so the early probes are at most
//! four. Under 25 packets four probes cannot complete a reading, and a short
//! probe that lost under 5 percent has shown that the startup's loss was its
//! own; either ends the repeat, and the bytes stay carried for the regular
//! probes. On a path with a clean limit the rule therefore costs one probe
//! about a second into the connection: half the window for 200 ms or one
//! smoothed RTT. The rules of this paragraph are ours.
//!
//! A new connection also starts as slow start does. Until its first startup has
//! ended, the window is at most the initial window plus the bytes acknowledged
//! so far, so it doubles per round trip at most. The startup gain alone would
//! let the first samples open the window to 2.89 times a bandwidth-delay
//! product at once. The controller had this limit through the window of
//! quinn's BBR while it was built around it, and keeps it as a rule of its
//! own. The limit does not come back when the startup gain does.
//!
//! A new connection uses a higher gain until its estimate stops growing. With
//! the window at 1.25 times the estimate, each sample can only show the rate
//! that window allows, so the estimate grows by at most 1.25 times per sample.
//! The startup gain is BBR's Startup gain, 2/ln 2, about 2.89. The estimate has
//! stopped growing when three samples in a row from intervals that were not
//! app-limited have not raised it by 25 percent since it last did. This is
//! BBR's full-bandwidth test. A congestion event also ends the startup when the
//! sample interval it falls in does not raise the estimate by 25 percent and
//! lost a share of its bytes above 1.5 times the base loss, whether or not
//! that interval was app-limited. An ECN mark ends it in such an interval at
//! any loss. With a base loss of zero that is any lost byte. Either applies
//! only once the startup has counted 100 packets of the current MTU,
//! acknowledged and lost, which departs from the exit as it was through 1.8.2.
//! Before that count the startup has measured nothing of the path: a handshake
//! is a few packets per round trip, app-limited, and one that lost a packet in
//! each of two round trips ended the startup on a dozen packets, so the
//! connection never ran one. On a path that drops a quarter of its packets
//! such a start is common, and in `line_sim` it then sent at its floor until a
//! regular probe 10 s or more later. The count cannot let a first startup
//! overshoot: 100 packets are at most 147 kB, under the initial window, and
//! until the first startup has ended the window is at most the initial window
//! plus the bytes acknowledged, so within those packets the startup gain sets
//! nothing. A startup that returns counts again from zero, but its window is
//! never below the initial window and no recovery limits it, so it counts 100
//! packets within its first sample interval unless the sender is held under
//! 100 packets in flight; in `line_sim` no returned startup reached its exit
//! under the count. Beyond the count, a first startup, which comes before the
//! first probe, and every startup on a path without base loss end as they did
//! before the base loss was read. On a path with base loss, a startup that
//! returns would otherwise end at its first interval without growth, far below
//! the path's rate. quinn reports a sender blocked by the peer's flow control
//! as app-limited. Behind a flow-control window smaller than the startup window
//! the full-bandwidth test therefore never runs, and without the congestion
//! exit the startup gain would stay. On a path with base loss such a sender
//! keeps the startup gain until an interval loses more than 1.5 times the base
//! loss.
//!
//! The startup gain returns when the estimate climbs back after a fall. The
//! estimate keeps a sample for ten intervals, so a loss episode longer than that
//! leaves only samples from the episode in it, and the window starts again from
//! its floor. At 1.25 the estimate then grows by about 12 percent per sample,
//! not 25, because a raised window shows in the sample about two round trips
//! later. So three samples in a row from intervals that were not app-limited,
//! each raising the estimate from below half of the highest estimate the
//! connection has had, bring the startup gain back, and the two rules above end
//! it again. Any rise counts, so a climb at 1.25 meets the rule within a few
//! samples. The rule is ours. The highest estimate does not expire, so on a
//! path whose rate has fallen for good, a later climb from below half of the
//! old rate also uses the startup gain, until the same two rules end it.
//!
//! A loss holds in-flight data for one round trip, by BBR's packet
//! conservation. The form here is ours, and it has the effect of the recovery
//! window of quinn's BBR. quinn reports a loss after the ACK batch that found
//! it, so the rule acts at the next batch. That batch sets a recovery window
//! of in-flight data plus the bytes it acknowledged, and never less than four
//! packets. Each later batch takes the bytes lost since the previous one off
//! the recovery window. Once a packet sent after the recovery began has been
//! acknowledged, each batch also adds the bytes it acknowledged. In-flight data
//! plus the bytes the batch acknowledged stays the recovery window's lower
//! bound. The recovery ends at the first batch without a loss that
//! acknowledges a packet sent after the last batch with one. The recovery
//! window limits the window only after the startup has ended, as quinn's BBR
//! applies its own only outside its Startup. An ECN mark loses no bytes and
//! starts no recovery.
//!
//! The minimum RTT expires. quinn's `RttEstimator::min` never does within a
//! path, so with it a lasting RTT rise would leave the window below the new
//! bandwidth-delay product, each delivery-rate sample would come out lower than
//! the last, and the window would fall to its floor. Expiry alone would not fix
//! that. A minimum measured again with the standing queue in it would raise the
//! window, and with it the queue, each time. So the controller empties the
//! queue before it measures, the way BBR's ProbeRTT does.
//!
//! A sample is the `now - sent` of an acknowledged packet. The peer's ACK
//! delay is part of it, which can only make it larger. The `now` can make it
//! smaller: quinn reads the clock once per endpoint poll and hands every ACK
//! of that poll the same value, so a poll that is held up between the clock
//! read and the socket read gives samples that are too short by the delay. One
//! such sample taken as the minimum holds the window under the
//! bandwidth-delay product for the 10 s it lasts, each delivery-rate sample
//! then comes out lower than the last, and nothing raises the estimate again:
//! in the lab a 60 ms path read as 37 ms once every 7 s carried 50 to 81
//! Mbit/s of 144. So the samples of one `now` count once. A sample under the
//! minimum lowers it when three values of `now` within a second have given
//! one, and the new minimum is the highest of the three lowest. A fall in the
//! path's RTT meets this with the third socket poll that reads an ACK. A
//! connection whose ACKs arrive less often than three polls in a second keeps
//! its minimum through such a fall; it sends too little for the window to
//! limit it, and the first bulk transfer confirms the lower minimum at once.
//! The rule is ours; BBR takes the
//! plain minimum, under a window gain of two that a short sample does not
//! bring under the bandwidth-delay product.
//!
//! A sample equal to the minimum restarts its 10 s lifetime, BBR's
//! MinRTTFilterLen. The first ACK after the lifetime ends that does not find
//! the sender app-limited starts a probe: the window is held at half the
//! estimated bandwidth-delay product, the target of BBRv2's ProbeRTT, and at
//! least four packets. Once in-flight data has fallen to that window, the probe
//! lasts 200 ms or one smoothed RTT, whichever is longer. The new minimum is
//! then taken from the samples since the probe started: the highest of the
//! lowest samples of the three values of `now` that gave the lowest ones,
//! without the limit of a second, or the lowest sample when the probe saw
//! fewer than three values of `now`. While the sender
//! is app-limited the probe does not start, because the window does not limit
//! an app-limited sender. ACKs that arrive during a probe count as app-limited
//! for the delivery rate, so the probe's own low samples do not lower the
//! estimate. Linux BBR does the same during ProbeRTT (`bbr_update_min_rtt` in
//! `net/ipv4/tcp_bbr.c`).
//!
//! A lasting RTT rise therefore lowers throughput until the next probe, which
//! starts 10 s after the minimum was last taken, or later while the sender is
//! app-limited. By then the estimate has fallen to what the floor carries, so
//! once the probe has taken the new minimum, the climb back to the new
//! bandwidth-delay product brings the startup gain back. A fall in RTT takes
//! effect with the third arrival that shows it. Each probe holds the window low for
//! about a quarter of a second.
//!
//! A delivery-rate sample is bounded by the send interval of its packets as
//! well as by its ACK interval (see `DeliveryRate`), because ACKs that arrive
//! together, as they do after a fall in RTT, would otherwise give a sample far
//! above what the path carries, and quinn's app-limited report for a
//! flow-control-blocked sender would keep the lower samples that follow out of
//! the estimate. One limit remains: quinn's app-limited flag is the
//! connection's state when the ACK arrives, not when the packet was sent, so
//! the first sample stored after ten or more unstored intervals, which replaces
//! the whole estimate, can measure packets sent while the sender was
//! app-limited and put the window about one round trip low until the next
//! sample.
//!
//! The window is computed when one of its inputs changes and stored, because
//! quinn reads it before every packet it sends. The inputs are the estimate,
//! the minimum RTT, the probe, the startup with its slow-start limit, the
//! steady gain, the base loss, the recovery window and the MTU.
//!
//! Lab measurements are in `docs/configuration.md`.

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;

mod base_loss;
mod gain;
#[cfg(test)]
mod line_sim;
mod min_rtt;
mod rate;
mod record;
mod recovery;
mod startup;
#[cfg(test)]
mod test_support;

use base_loss::{BaseLoss, Closed, READING_PACKETS};
use gain::{Gain, WINDOW_PACKETS};
use min_rtt::{LowSamples, Probe};
use rate::{DeliveryRate, Sample};
use record::Counted;
pub use record::Record;
use recovery::Recovery;
use startup::Startup;

/// The window a connection starts with, and the floor of the window outside a
/// probe: 200 packets of 1200 bytes, the default initial window of the BBR in
/// quinn-proto 0.11 (`quinn::congestion::BbrConfig::default()`), which this
/// controller replaced.
const INITIAL_WINDOW: u64 = 200 * 1200;

/// The probe window as a multiple of the estimated bandwidth-delay product, in
/// per mille: half, the target of BBRv2's ProbeRTT.
const PROBE_GAIN_PERMILLE: u128 = 500;

/// The window until the estimate stops growing, in per mille: BBR's Startup
/// gain, 2/ln 2, to three decimals.
const STARTUP_GAIN_PERMILLE: u128 = 2_885;

/// How long a sample under the minimum waits for the others that confirm it.
const LOW_SAMPLE_LIFETIME: Duration = Duration::from_secs(1);

/// How long a minimum RTT holds without a sample equal to it or a confirmed
/// lower one before a probe measures it again: BBR's MinRTTFilterLen.
const MIN_RTT_LIFETIME: Duration = Duration::from_secs(10);

/// How many sample intervals after a first reading of 5 percent or more the
/// probe that confirms it is due: the estimate's window, so that the reading
/// acts for about as long as the estimate holds a sample. Our own value.
const CONFIRM_INTERVALS: usize = rate::SAMPLES;

/// The shortest time a probe holds its window once in-flight data has fallen
/// to it: BBR's ProbeRTTDuration.
const PROBE_TIME: Duration = Duration::from_millis(200);

/// The smallest probe window and the smallest recovery window, in packets:
/// BBR's minimum congestion window.
const MIN_WINDOW_PACKETS: u64 = 4;

/// How old a packet must be, as a multiple of the round-trip time, before
/// quinn declares it lost once a later packet has been acknowledged.
///
/// quinn's default is 9/8, the value RFC 9002 section 6.1.2 recommends. The
/// same section notes: "TCP's RACK \[RFC8985\] specifies a slightly larger
/// threshold, equivalent to 5/4, for a similar purpose." It allows other
/// values and names what they cost: "Smaller thresholds reduce reordering
/// resilience and increase spurious retransmissions, and larger thresholds
/// increase loss detection delay." RFC 8985 section 6.2, step 4, gives RACK's
/// value: "it starts with a conservative RACK.reo_wnd of RACK.min_RTT/4."
///
/// The round-trip time quinn multiplies is the larger of the smoothed one and
/// the latest sample, so the allowance for a late packet is a quarter of it:
/// 15 ms on a 60 ms path. On the path that `LOSS_PACKET_THRESHOLD` in
/// `src/quic/transport.rs` describes, 57 to 67 percent of the late packets
/// were under an eighth of the round-trip time late and 82 to 85 percent under
/// a quarter, which is why 9/8 left 43 to 46 percent of them declared lost and
/// 5/4 leaves 13 to 28. The price is that a packet that really was lost is
/// sent again an eighth of a round trip later than with 9/8.
///
/// That delay matters where flow control is tight. Data sent after a lost
/// packet counts against the peer's connection window, and against
/// `SEND_WINDOW` in `src/quic/transport.rs`, until the packet has been sent
/// again and acknowledged, about 2.25 round trips after it was first sent
/// where the defaults take about 2. In the lab at 150 Mbit/s over 60 ms with 2
/// or 5 percent of the packets dropped and nothing reordered, a client with a
/// 4 MiB connection window received 6 to 8 percent less with these values than
/// with quinn's defaults, and a client with a 16 MiB window, which is what
/// Surge advertises, received the same. With reordering as on the production
/// path, the lab carried 128 to 135 Mbit/s where the defaults carried 91 to
/// 92.
///
/// `src/quic/transport.rs` gives this value to quinn. The congestion
/// controller reads it too: a lost packet stays in flight for this many round
/// trips, and the window covers that on a path with base loss
/// ([`LOSS_DELAY_EXTRA_PERMILLE`]). It is defined here, beside the window that
/// reads it, so that the transport imports from this module and this module
/// imports nothing from the transport.
pub(crate) const LOSS_TIME_THRESHOLD: f32 = 1.25;

/// How much longer than a round trip a lost packet stays in flight, in per
/// mille of a round trip: quinn's time threshold minus one, taken from
/// [`LOSS_TIME_THRESHOLD`] above so that the two cannot differ. quinn
/// declares a packet lost once a later one has been acknowledged and its age
/// is the threshold times the RTT.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
const LOSS_DELAY_EXTRA_PERMILLE: u128 = ((LOSS_TIME_THRESHOLD - 1.0) * 1000.0) as u128;

const _: () = assert!(
    LOSS_DELAY_EXTRA_PERMILLE <= 1000,
    "a threshold over two round trips is not what the window covers"
);

/// Builds [`Bbr`] controllers.
#[derive(Debug, Clone, Default)]
pub struct BbrConfig;

impl ControllerFactory for BbrConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Bbr {
            rate: DeliveryRate::default(),
            startup: Startup::default(),
            min_rtt: None,
            low: LowSamples::default(),
            probe: None,
            srtt: Duration::ZERO,
            mtu: current_mtu.into(),
            acked: 0,
            lost: 0,
            recovery: None,
            slow_start: Some(INITIAL_WINDOW),
            gain: Gain::default(),
            base: BaseLoss::default(),
            probe_due: false,
            repeat: false,
            confirm: None,
            #[cfg(test)]
            last_closed: None,
            #[cfg(test)]
            exit_packets: READING_PACKETS,
            cap: None,
            window: INITIAL_WINDOW,
            record: Record::default(),
            flight: (0, 0),
        })
    }
}

/// A controller whose window is at most 1.25 times the measured
/// bandwidth-delay product, plus what the path's own loss takes out of it.
/// See the [module documentation](self).
#[derive(Debug, Clone)]
pub struct Bbr {
    rate: DeliveryRate,
    startup: Startup,
    /// The minimum RTT and when it was taken or last renewed; `None` before
    /// the first ACK.
    min_rtt: Option<(Duration, Instant)>,
    /// The samples under the minimum that are not confirmed yet, and during a
    /// probe the lowest samples of the probe.
    low: LowSamples,
    /// The probe in progress, if any.
    probe: Option<Probe>,
    /// quinn's smoothed RTT as it was before the latest ACK frame, since quinn
    /// updates it after `on_ack` and `on_end_acks`: how long a sample interval
    /// lasts.
    srtt: Duration,
    mtu: u64,
    /// Bytes acknowledged since the last ACK batch ended.
    acked: u64,
    /// Bytes lost since the last ACK batch ended.
    lost: u64,
    /// The recovery in progress, if any.
    recovery: Option<Recovery>,
    /// The slow-start limit of a new connection: the initial window plus the
    /// bytes acknowledged so far. `None` once the first startup has ended.
    slow_start: Option<u64>,
    /// The steady gain and the loss windows that move it.
    gain: Gain,
    /// The path's base loss and the reading in progress.
    base: BaseLoss,
    /// Whether the minimum RTT's lifetime is treated as over, so that a probe
    /// starts at the next ACK that does not find the sender app-limited: set
    /// when a startup that lost [`base_loss::EARLY_PROBE_PPM`] of its bytes
    /// or more ends with no reading kept, again for `repeat`, and when
    /// `confirm` runs out.
    probe_due: bool,
    /// Whether the early probe repeats: set with `probe_due` at the end of a
    /// startup. Cleared once a reading is kept, when a probe closes short
    /// having counted under a quarter of [`READING_PACKETS`] or with its carry
    /// under [`base_loss::EARLY_PROBE_PPM`] lost, and when a probe is
    /// unverified or clears the base loss. A probe dropped as an outage leaves
    /// it as it is. While it is set, a probe whose reading closes short makes
    /// the next one due at once.
    repeat: bool,
    /// Sample intervals, not counting those of a probe, until the probe that
    /// confirms a first reading is due.
    confirm: Option<usize>,
    /// When the latest reading closed and what became of it, for `line_sim`.
    #[cfg(test)]
    last_closed: Option<(Instant, Closed)>,
    /// What [`Bbr::exit_packets`] returns; zero runs the startup's exit as it
    /// was before.
    #[cfg(test)]
    exit_packets: u64,
    /// What [`Bbr::compute_cap`] returned when an input last changed.
    cap: Option<u64>,
    /// What [`Controller::window`] returns: the cap, or the initial window
    /// while there is none, lowered to the slow-start limit during the first
    /// startup and to the recovery window after the startup.
    window: u64,
    /// What the connection's close line reports; see [`Record`].
    record: Record,
    /// The bytes acknowledged since the last sample interval closed, and the
    /// sum of their times in flight in byte-microseconds, for `record`.
    flight: (u64, u128),
}

impl Bbr {
    /// What the controller has counted for the connection's close line.
    pub fn record(&self) -> Record {
        self.record
    }

    /// The part of [`Controller::on_ack`] that is ours, split out because
    /// [`RttEstimator`] has no public constructor and the tests cannot make one.
    fn record_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        srtt: Duration,
    ) {
        self.srtt = srtt;
        let rtt = now.saturating_duration_since(sent);
        self.flight.0 = self.flight.0.saturating_add(bytes);
        self.flight.1 = self
            .flight
            .1
            .saturating_add(u128::from(bytes) * rtt.as_micros());
        self.acked = self.acked.saturating_add(bytes);
        self.gain.on_ack(bytes);
        self.startup.on_ack(bytes);
        self.base.on_ack(sent, bytes);
        if let Some(limit) = &mut self.slow_start {
            *limit = limit.saturating_add(bytes);
        }
        // A probe holds the window below the path's rate on purpose, so its ACKs
        // count as app-limited and its low samples do not lower the estimate.
        let probing = self.probe.is_some();
        self.rate.on_ack(sent, bytes, app_limited || probing);
        if let Some(probe) = &mut self.probe {
            probe.min = probe.min.min(rtt);
            self.low.add(now, rtt, None);
            return;
        }
        match self.min_rtt {
            Some((min, at)) if rtt > min => {
                let expired =
                    self.probe_due || now.saturating_duration_since(at) > MIN_RTT_LIFETIME;
                if !app_limited && expired {
                    self.probe_due = false;
                    // The round trip before the probe, by send time.
                    self.base.enter(now, min);
                    self.probe = Some(Probe {
                        min: rtt,
                        ends: None,
                    });
                    self.low = LowSamples::default();
                    self.low.add(now, rtt, None);
                    self.refresh();
                }
            }
            // An equal sample only restarts the lifetime.
            Some((min, _)) if rtt == min => self.min_rtt = Some((rtt, now)),
            // A lower sample waits for two more arrival times that confirm it.
            Some(_) => {
                self.low.add(now, rtt, Some(LOW_SAMPLE_LIFETIME));
                if let Some(confirmed) = self.low.confirmed() {
                    self.min_rtt = Some((confirmed, now));
                    self.low = LowSamples::default();
                    self.refresh();
                }
            }
            None => {
                self.min_rtt = Some((rtt, now));
                self.refresh();
            }
        }
    }

    /// Starts the probe's clock once in-flight data has fallen to the probe
    /// window, and ends the probe when that time is up. Returns whether the
    /// probe ended.
    fn update_probe(&mut self, now: Instant, in_flight: u64) -> bool {
        let cap = self.cap;
        let Some(probe) = &mut self.probe else {
            return false;
        };
        match probe.ends {
            None if cap.is_none_or(|cap| in_flight <= cap) => {
                probe.ends = Some(now + PROBE_TIME.max(self.srtt));
                self.base.begin(now);
            }
            Some(ends) if now >= ends => {
                self.base.end(now);
                // A probe too short for the confirmations takes its lowest sample.
                let min = self.low.confirmed().unwrap_or(probe.min);
                self.min_rtt = Some((min, now));
                self.low = LowSamples::default();
                self.probe = None;
                return true;
            }
            _ => {}
        }
        false
    }

    /// The packets of the current MTU a startup counts before one interval
    /// can end it: [`READING_PACKETS`].
    #[cfg(not(test))]
    fn exit_packets(&self) -> u64 {
        READING_PACKETS
    }

    /// The packets of the current MTU a startup counts before one interval
    /// can end it: [`READING_PACKETS`] unless a test has set another value.
    #[cfg(test)]
    fn exit_packets(&self) -> u64 {
        self.exit_packets
    }

    /// Stores the cap and the window after a change to one of their inputs.
    fn refresh(&mut self) {
        self.cap = self.compute_cap();
        let window = self.cap.unwrap_or(INITIAL_WINDOW);
        let window = self.slow_start.map_or(window, |limit| window.min(limit));
        self.window = match self.recovery {
            Some(recovery) if self.startup.ended => window.min(recovery.window),
            _ => window,
        };
    }

    /// One debug line per delivery-rate sample, with the terms that limit the
    /// window after the ACK batch that closed it. Off under the shipped
    /// `volto=info` filter.
    fn trace(&self, sample: &Sample, in_flight: u64) {
        tracing::debug!(
            sample_bytes_per_sec = sample.rate,
            estimate_bytes_per_sec = self.rate.max().unwrap_or(0),
            cap_bytes = self.cap.unwrap_or(0),
            recovery_bytes = self.recovery.map_or(0, |r| r.window),
            window_bytes = self.window,
            in_flight_bytes = in_flight,
            min_rtt_us = self.min_rtt.map_or_default(|(min, _)| min.as_micros()),
            srtt_us = self.srtt.as_micros(),
            ack_interval_us = sample.ack_elapsed.as_micros(),
            send_interval_us = sample.send_elapsed.as_micros(),
            gain_permille = self.gain.permille,
            base_loss_ppm = self.base.ppm(),
            startup = !self.startup.ended,
            app_limited = sample.app_limited,
            stored = sample.stored,
            probing = self.probe.is_some(),
            "bbr sample"
        );
    }

    /// The window limit, once there is a delivery-rate sample to compute it
    /// from: the steady gain times the bandwidth-delay product, the startup
    /// gain times it until the startup has ended, or half of it during a probe.
    /// The steady window also covers the base loss `p`: it is multiplied by
    /// (1 + t p) / (1 - p), where t is [`LOSS_DELAY_EXTRA_PERMILLE`].
    ///
    /// Outside a probe the limit is never below [`INITIAL_WINDOW`], so a
    /// connection that has measured a low rate is never slower to send than a
    /// fresh one.
    fn compute_cap(&self) -> Option<u64> {
        let bandwidth = self.rate.max()?;
        let (min_rtt, _) = self.min_rtt?;
        let (gain_permille, floor) = match self.probe {
            None if self.startup.ended => (u128::from(self.gain.permille), INITIAL_WINDOW),
            None => (STARTUP_GAIN_PERMILLE, INITIAL_WINDOW),
            Some(_) => (PROBE_GAIN_PERMILLE, MIN_WINDOW_PACKETS * self.mtu),
        };
        // Bytes per second times microseconds times per mille.
        let mut bytes = u128::from(bandwidth) * min_rtt.as_micros() * gain_permille / 1_000_000_000;
        if self.probe.is_none() && self.startup.ended {
            // Parts per million times per mille.
            let base = u128::from(self.base.ppm());
            bytes = bytes * (1_000_000_000 + LOSS_DELAY_EXTRA_PERMILLE * base)
                / (1_000_000u128.saturating_sub(base).max(1) * 1_000);
        }
        Some(u64::try_from(bytes).unwrap_or(u64::MAX).max(floor))
    }
}

impl Controller for Bbr {
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.record_ack(now, sent, bytes, app_limited, rtt.get());
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        let sample = self.rate.on_end_acks(now, app_limited, self.srtt);
        if let Some(sample) = &sample {
            let was_ended = self.startup.ended;
            // The close line's counts, read before this interval moves the
            // startup, the estimate and the cap, and before the startup takes
            // the interval's lost bytes. A probe's ACKs count as app-limited,
            // so an interval with a probe in it is left out with the others.
            let flight = std::mem::take(&mut self.flight);
            if was_ended && !sample.app_limited {
                self.record.count(Counted {
                    length: sample.ack_elapsed,
                    rate: sample.rate,
                    at_floor: self.cap.is_some_and(|cap| cap <= INITIAL_WINDOW),
                    lossless: self.startup.lossless(),
                    window: self.window,
                    flight,
                    min_rtt: self.min_rtt.map_or(Duration::ZERO, |(min, _)| min),
                    base_loss_ppm: self.base.ppm(),
                    gain_permille: self.gain.permille,
                });
            }
            // 1.5 times the base loss: any lost byte while it is zero.
            let exit_above = self.base.ppm() * 3 / 2;
            self.startup.on_interval(
                self.rate.max().unwrap_or(0),
                sample.app_limited,
                exit_above,
                self.exit_packets() * self.mtu,
            );
            if self.startup.ended
                && !was_ended
                && !self.base.has_reading()
                && self.startup.lost_ppm() >= self.base.early_probe_ppm()
            {
                self.probe_due = true;
                self.repeat = true;
            }
            if self.startup.ended {
                self.slow_start = None;
                let estimate = self.rate.max().unwrap_or(0);
                let packets = WINDOW_PACKETS * self.mtu;
                let probing = self.probe.is_some();
                self.gain.on_interval(
                    probing,
                    sample.app_limited,
                    estimate,
                    packets,
                    self.base.ppm(),
                );
            } else {
                self.gain = Gain::default();
            }
            if self.probe.is_none()
                && let Some(left) = self.confirm
            {
                if left <= 1 {
                    self.confirm = None;
                    self.probe_due = true;
                } else {
                    self.confirm = Some(left - 1);
                }
            }
            self.refresh();
        }
        if self.update_probe(now, in_flight) {
            self.refresh();
        }
        let least = READING_PACKETS * self.mtu;
        let was_zero = self.base.ppm() == 0;
        let closed = self.base.close(now, self.srtt, least);
        if let Closed::Kept { .. } = closed
            && was_zero
            && self.base.ppm() >= self.base.early_probe_ppm()
        {
            // A reading that takes the base loss up from zero acts at once
            // and is confirmed by one more probe.
            self.confirm = Some(CONFIRM_INTERVALS);
        }
        if closed != Closed::No {
            #[cfg(test)]
            {
                self.last_closed = Some((now, closed));
            }
            tracing::debug!(
                outcome = ?closed,
                base_loss_ppm = self.base.ppm(),
                "bbr reading"
            );
        }
        if let Closed::Unverified { .. } | Closed::Cleared { .. } = closed {
            // What arrived did not fall with what was sent: the startup's
            // loss was a limit's, and probing again soon tells nothing more.
            self.repeat = false;
        }
        if let Closed::Short { own, lost_ppm, .. } = closed
            && self.repeat
        {
            // At least a quarter of a reading, so that four such probes
            // complete one, and a loss that a reading is needed for. Under
            // either, the regular probes take the carry further.
            if own.saturating_mul(4) >= least && lost_ppm >= self.base.early_probe_ppm() {
                self.probe_due = true;
            } else {
                self.repeat = false;
            }
        }
        if self.base.has_reading() {
            self.repeat = false;
        }
        if closed != Closed::No {
            self.refresh();
        }
        // The slow-start limit moved with the bytes this batch acknowledged.
        if self.update_recovery(now, in_flight) || self.slow_start.is_some() {
            self.refresh();
        }
        if let Some(sample) = &sample {
            self.trace(sample, in_flight);
        }
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.startup.on_loss(lost_bytes);
        self.base.on_loss(sent, lost_bytes);
        self.lost = self.lost.saturating_add(lost_bytes);
        self.gain.on_loss(lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu.into();
        self.refresh();
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        INITIAL_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::gain::SETTLE_INTERVALS;
    use super::gain::{lowered, settled};
    use super::rate::SAMPLES;
    use super::test_support::{SRTT, ms};
    use super::*;

    const MIN_RTT: Duration = Duration::from_millis(60);

    /// [`INITIAL_WINDOW`], 200 packets of 1200 bytes, which is the floor of the
    /// cap outside a probe.
    const FLOOR: u64 = 240_000;
    /// The bandwidth estimate of [`estimated`], 120 Mbit/s.
    const BANDWIDTH: u64 = 15_000_000;

    impl Bbr {
        /// The stored window limit; `None` before there is a delivery-rate
        /// sample and a minimum RTT to compute it from.
        fn cap(&self) -> Option<u64> {
            self.cap
        }
    }

    /// The controller the default factory builds at `mtu`.
    fn build(mtu: u16) -> Bbr {
        *Arc::new(BbrConfig)
            .build(Instant::now(), mtu)
            .into_any()
            .downcast::<Bbr>()
            .expect("the factory builds a Bbr")
    }

    /// A controller as the default factory builds it, still in its startup.
    fn starting() -> Bbr {
        build(1200)
    }

    /// [`starting`] with the startup ended, so that the cap is 1.25 times the
    /// bandwidth-delay product.
    fn capped() -> Bbr {
        let mut c = starting();
        c.startup.ended = true;
        c.slow_start = None;
        c
    }

    /// A controller whose bandwidth estimate is [`BANDWIDTH`] in every slot, so
    /// that the empty samples a test's batch ends add do not lower it, and
    /// whose minimum RTT is [`MIN_RTT`], taken at `t0`. Its cap is 1.125 MB.
    fn estimated(t0: Instant) -> Bbr {
        let mut c = capped();
        c.rate.samples = [BANDWIDTH; SAMPLES];
        ack(&mut c, t0, MIN_RTT, 0, false);
        c
    }

    /// An ACK at `at` of `bytes` sent `rtt` before it.
    fn ack(c: &mut Bbr, at: Instant, rtt: Duration, bytes: u64, app_limited: bool) {
        c.record_ack(at, at - rtt, bytes, app_limited, SRTT);
    }

    fn end_acks(c: &mut Bbr, at: Instant, app_limited: bool) {
        c.on_end_acks(at, 0, app_limited, None);
    }

    /// Runs one sample interval of `SRTT`, starting where the previous one
    /// ended, whose sample is `rate` bytes per second, and returns when it
    /// ended. `SRTT` is a tenth of a second, so the interval acknowledges a
    /// tenth of `rate`.
    fn interval(c: &mut Bbr, start: Instant, rate: u64, app_limited: bool) -> Instant {
        let end = start + SRTT;
        ack(c, end, MIN_RTT, rate / 10, app_limited);
        end_acks(c, end, app_limited);
        end
    }

    /// The loss window's 2000 packets are packets of the current MTU.
    #[test]
    fn the_loss_window_counts_packets_of_the_current_mtu() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        c.mtu = 1400;
        c.gain = settled();
        end_acks(&mut c, t0, false);
        let mut t = t0;
        // 2000 packets of 1400 bytes are 2.8 MB. Each interval acknowledges
        // 0.65 MB and loses 0.05 MB, so the window closes with the fourth.
        for _ in 0..3 {
            c.on_congestion_event(t, t - MIN_RTT, false, 50_000);
            t = interval(&mut c, t, 6_500_000, false);
        }
        assert_eq!((c.gain.permille, c.gain.intervals), (1250, 3));
        c.on_congestion_event(t, t - MIN_RTT, false, 50_000);
        t = interval(&mut c, t, 6_500_000, false);
        assert_eq!(c.gain.recent_len, 1, "a window");
        for _ in 0..12 {
            c.on_congestion_event(t, t - MIN_RTT, false, 50_000);
            t = interval(&mut c, t, 6_500_000, false);
        }
        assert_eq!(c.gain.permille, 1160, "1250 x (1 - 0.2 / 2.8)");

        let mut c = estimated(t0);
        c.mtu = 1500;
        c.gain = settled();
        end_acks(&mut c, t, false);
        for _ in 0..4 {
            c.on_congestion_event(t, t - MIN_RTT, false, 50_000);
            t = interval(&mut c, t, 6_500_000, false);
        }
        assert_eq!(
            (c.gain.recent_len, c.gain.intervals),
            (0, 4),
            "2.8 MB is under 2000 packets of 1500"
        );
    }

    /// The controller feeds the loss windows from its ACKs and losses, and its
    /// cap follows the gain.
    #[test]
    fn the_stored_window_follows_the_steady_gain() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        c.mtu = 1200;
        c.gain = settled();
        end_acks(&mut c, t0, false);
        let mut t = t0;
        // Three loss windows of four intervals and three intervals of the
        // fourth.
        for _ in 0..15 {
            c.on_congestion_event(t, t - MIN_RTT, false, 125_000);
            t = interval(&mut c, t, BANDWIDTH, false);
            assert_eq!(c.cap(), Some(1_125_000), "1.25 x 15 MB/s x 60 ms");
        }
        c.on_congestion_event(t, t - MIN_RTT, false, 125_000);
        interval(&mut c, t, BANDWIDTH, false);
        // 125 kB lost for 1.5 MB acknowledged is 7.6923 percent.
        assert_eq!(c.gain.permille, 1153, "1250 x 0.923077");
        assert_eq!(c.cap(), Some(1_037_700), "1.153 x 15 MB/s x 60 ms");
    }

    #[test]
    fn the_gain_starts_again_when_the_startup_gain_returns() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        end_acks(&mut c, t0, false);
        c.gain = lowered(1100);
        c.gain.floor = 1150;
        let t = interval(&mut c, t0, BANDWIDTH, false);
        assert_eq!(c.gain.permille, 1100, "kept while the startup has ended");
        c.startup.ended = false;
        interval(&mut c, t, BANDWIDTH, false);
        assert_eq!(c.gain, Gain::default());
    }

    /// A probe's intervals count as probing for the gain as well.
    #[test]
    fn a_probe_restarts_the_controllers_loss_window() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        end_acks(&mut c, t0, false);
        c.gain.settle = 0;
        let t = interval(&mut c, t0, BANDWIDTH, false);
        assert_eq!(c.gain.intervals, 1);
        c.probe = Some(Probe {
            min: MIN_RTT,
            ends: None,
        });
        interval(&mut c, t, BANDWIDTH, false);
        assert_eq!((c.gain.intervals, c.gain.settle), (0, SETTLE_INTERVALS));
    }

    #[test]
    fn the_factory_starts_a_connection_in_its_startup_at_quinns_mtu() {
        let c = build(1300);
        assert_eq!(c.initial_window(), FLOOR);
        assert_eq!(c.window(), FLOOR);
        assert_eq!(c.mtu, 1300);
        assert!(!c.startup.ended, "a new connection starts in its startup");
        assert!(c.min_rtt.is_none() && c.probe.is_none() && c.rate.max().is_none());
        assert!(c.recovery.is_none());
    }

    /// The window is the cap, and outside a probe the cap is
    /// `max(gain x bandwidth-delay product, initial window)`.
    #[test]
    fn the_window_is_the_cap_and_the_cap_never_goes_below_the_initial_window() {
        // The bytes acknowledged and how long after the interval started, then
        // the cap and the window.
        for (bytes, after, cap, window, case) in [
            (
                1_500_000,
                SRTT - ms(1),
                None,
                FLOOR,
                "no sample yet, so no cap",
            ),
            (
                10_000,
                SRTT,
                Some(FLOOR),
                FLOOR,
                "1.25 x 100 kB/s x 60 ms is below the floor",
            ),
            (
                1_500_000,
                SRTT,
                Some(1_125_000),
                1_125_000,
                "1.25 x 15 MB/s x 60 ms",
            ),
        ] {
            let mut c = capped();
            let t0 = Instant::now();
            end_acks(&mut c, t0, false);
            ack(&mut c, t0 + after, MIN_RTT, bytes, false);
            end_acks(&mut c, t0 + after, false);

            assert_eq!(c.cap(), cap, "{case}");
            assert_eq!(c.window(), window, "{case}");
            let metrics = c.metrics();
            assert_eq!(metrics.congestion_window, window, "{case}");
            assert_eq!(
                metrics.pacing_rate, None,
                "{case}: quinn paces from the window"
            );
        }
    }

    /// Before the first sample there is no cap, and the window is the initial
    /// window however many bytes are acknowledged: it does not grow by them,
    /// and a loss during the startup does not lower it.
    #[test]
    fn before_the_first_sample_the_window_is_the_initial_window() {
        let mut c = starting();
        let t0 = Instant::now();
        end_acks(&mut c, t0, false);
        for n in 1..=9 {
            let at = t0 + ms(10 * n);
            ack(&mut c, at, MIN_RTT, 200_000, false);
            c.on_congestion_event(at, at - MIN_RTT, false, 1200);
            c.on_end_acks(at, 500_000, false, None);
            assert_eq!(c.cap(), None, "no interval has closed at {n}0 ms");
            assert_eq!(c.window(), FLOOR, "at {n}0 ms");
        }
        assert_eq!(c.min_rtt.map(|(min, _)| min), Some(MIN_RTT));

        ack(&mut c, t0 + SRTT, MIN_RTT, 200_000, false);
        end_acks(&mut c, t0 + SRTT, false);
        assert_eq!(c.cap(), Some(3_462_000), "2.885 x 20 MB/s x 60 ms");
        assert_eq!(
            c.window(),
            2_240_000,
            "the slow-start limit: 240 kB plus the 2 MB acknowledged"
        );
    }

    /// During the first startup the window follows the bytes acknowledged
    /// batch by batch, and the limit ends with that startup for good.
    #[test]
    fn the_slow_start_limit_moves_with_each_batch_and_ends_with_the_first_startup() {
        let t0 = Instant::now();
        let mut c = starting();
        c.rate.samples = [BANDWIDTH; SAMPLES];
        ack(&mut c, t0, MIN_RTT, 0, false);
        end_acks(&mut c, t0, false);
        assert_eq!(c.cap(), Some(2_596_500), "2.885 x 15 MB/s x 60 ms");
        assert_eq!(c.window(), FLOOR, "nothing acknowledged yet");

        // A batch that closes no sample interval still moves the limit.
        ack(&mut c, t0 + ms(10), MIN_RTT, 50_000, false);
        end_acks(&mut c, t0 + ms(10), false);
        assert_eq!(c.window(), FLOOR + 50_000);

        let mut t = t0 + ms(10);
        while !c.startup.ended {
            t = interval(&mut c, t, BANDWIDTH, false);
        }
        assert_eq!(c.slow_start, None);
        assert_eq!(Some(c.window()), c.cap(), "the cap alone after the startup");

        // The startup gain comes back; the limit does not.
        c.startup = Startup::default();
        c.refresh();
        assert_eq!(c.cap(), Some(2_596_500));
        assert_eq!(c.window(), 2_596_500);
    }

    #[test]
    fn a_sample_is_the_bytes_acked_over_one_round_trip_and_sets_the_cap() {
        let mut c = capped();
        let t0 = Instant::now();
        // Bytes acknowledged by the batch that opens the interval were delivered
        // before it, so they are not part of the sample.
        ack(&mut c, t0, MIN_RTT, 999_999, false);
        end_acks(&mut c, t0, false);
        ack(&mut c, t0 + ms(40), MIN_RTT, 1_000_000, false);
        end_acks(&mut c, t0 + ms(40), false);
        ack(&mut c, t0 + SRTT, MIN_RTT, 500_000, false);
        end_acks(&mut c, t0 + SRTT, false);

        assert_eq!(c.rate.max(), Some(15_000_000), "1.5 MB over 100 ms");
        assert_eq!(c.cap(), Some(1_125_000), "1.25 x 15 MB/s x 60 ms");
    }

    #[test]
    fn an_app_limited_round_can_raise_the_estimate_but_not_lower_it() {
        let mut c = capped();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 10_000_000, true);
        assert_eq!(
            c.rate.max(),
            Some(10_000_000),
            "the first sample raises it from none"
        );
        // Fill the other nine slots, so that one more sample would push the
        // 10 MB/s one out.
        for _ in 1..SAMPLES {
            t = interval(&mut c, t, 5_000_000, false);
        }

        // Either flag marks the round: one app-limited ACK, or the batch end.
        t += SRTT;
        ack(&mut c, t, MIN_RTT, 100_000, true);
        end_acks(&mut c, t, false);
        t += SRTT;
        ack(&mut c, t, MIN_RTT, 100_000, false);
        end_acks(&mut c, t, true);
        for _ in 0..SAMPLES {
            t = interval(&mut c, t, 1_000_000, true);
        }
        assert_eq!(
            c.rate.max(),
            Some(10_000_000),
            "lower app-limited samples are skipped, so they push nothing out"
        );

        interval(&mut c, t, 19_000_000, true);
        assert_eq!(c.rate.max(), Some(19_000_000), "a higher one counts");
    }

    #[test]
    fn an_ack_compressed_round_is_measured_over_the_time_its_packets_were_sent() {
        let mut c = capped();
        let t0 = Instant::now();
        // The path RTT has just fallen from 140 to 60 ms, so the ACKs for 1.8 MB
        // sent over 180 ms, from t0 - 140 ms to t0 + 40 ms, arrive within one
        // 100 ms round. Each packet's send time is its ACK time minus its RTT.
        ack(&mut c, t0, ms(140), 1_000_000, false);
        end_acks(&mut c, t0, false);
        ack(&mut c, t0 + ms(10), ms(110), 1_000_000, false);
        ack(&mut c, t0 + SRTT, ms(60), 700_000, false);
        // Acknowledged out of order: sent at t0 - 120 ms, before the latest
        // packet.
        ack(&mut c, t0 + SRTT, ms(220), 100_000, false);
        end_acks(&mut c, t0 + SRTT, false);
        assert_eq!(
            c.rate.max(),
            Some(10_000_000),
            "1.8 MB over the 180 ms they were sent in, not the 100 ms of ACKs"
        );

        // The next round's send time starts at the latest packet of this one,
        // t0 + 40 ms, and ends at t0 + 140 ms.
        ack(&mut c, t0 + ms(200), ms(60), 1_200_000, false);
        end_acks(&mut c, t0 + ms(200), false);
        assert_eq!(c.rate.max(), Some(12_000_000), "1.2 MB over 100 ms");

        // Sent in 100 ms, up to t0 + 240 ms, and acknowledged over 150 ms: the
        // ACK interval counts.
        ack(&mut c, t0 + ms(350), ms(110), 2_250_000, false);
        end_acks(&mut c, t0 + ms(350), false);
        assert_eq!(c.rate.max(), Some(15_000_000), "2.25 MB over 150 ms");
    }

    #[test]
    fn the_estimate_forgets_a_sample_after_ten_newer_ones() {
        let mut c = capped();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 30_000_000, false);
        for _ in 1..SAMPLES {
            t = interval(&mut c, t, 10_000_000, false);
        }
        assert_eq!(c.rate.max(), Some(30_000_000), "still within the last ten");

        interval(&mut c, t, 10_000_000, false);
        assert_eq!(c.rate.max(), Some(10_000_000));
        assert_eq!(c.cap(), Some(750_000), "1.25 x 10 MB/s x 60 ms");
    }

    #[test]
    fn a_sample_expires_ten_intervals_later_even_when_they_stored_nothing() {
        let mut c = capped();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 30_000_000, false);
        t = interval(&mut c, t, 12_000_000, false);
        for _ in 2..SAMPLES {
            t = interval(&mut c, t, 1_000_000, true);
        }
        assert_eq!(
            c.rate.max(),
            Some(30_000_000),
            "nothing was stored, so the estimate holds"
        );

        t = interval(&mut c, t, 10_000_000, false);
        assert_eq!(
            c.rate.max(),
            Some(12_000_000),
            "the next stored sample expires the one ten intervals old"
        );
        interval(&mut c, t, 10_000_000, false);
        assert_eq!(c.rate.max(), Some(10_000_000));
    }

    #[test]
    fn a_zero_sample_expires_nothing() {
        let mut c = capped();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 30_000_000, false);
        for _ in 1..SAMPLES {
            t = interval(&mut c, t, 1_000_000, true);
        }
        interval(&mut c, t, 0, false);
        assert_eq!(
            c.rate.max(),
            Some(30_000_000),
            "a zero sample ten intervals later keeps the estimate"
        );
        assert!(c.cap().is_some(), "the cap stays while the estimate holds");
    }

    #[test]
    fn a_cap_too_large_for_u64_saturates_instead_of_wrapping() {
        let mut c = capped();
        c.rate.samples[0] = u64::MAX;
        c.min_rtt = Some((Duration::from_secs(1), Instant::now()));
        c.refresh();

        assert_eq!(c.cap(), Some(u64::MAX));
        assert_eq!(c.window(), u64::MAX);
    }

    #[test]
    fn the_minimum_rtt_is_renewed_by_a_sample_at_or_below_it_and_expires_after_10_s() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        ack(&mut c, t0 + ms(1_000), ms(70), 0, false);
        assert_eq!(c.cap(), Some(1_125_000), "a higher sample leaves it");
        ack(&mut c, t0 + ms(4_998), ms(55), 0, false);
        ack(&mut c, t0 + ms(4_999), ms(55), 0, false);
        assert_eq!(c.cap(), Some(1_125_000), "two lower arrivals leave it");
        ack(&mut c, t0 + ms(5_000), ms(55), 0, false);
        assert_eq!(c.cap(), Some(1_031_250), "the third replaces it");
        ack(&mut c, t0 + ms(9_000), ms(55), 0, false);

        // The equal sample at 9 s renewed it, so 10 s after that it still holds.
        ack(&mut c, t0 + ms(19_000), ms(70), 0, false);
        assert!(c.probe.is_none());
        assert_eq!(c.cap(), Some(1_031_250));

        ack(&mut c, t0 + ms(19_001), ms(70), 0, false);
        assert!(
            c.probe.is_some(),
            "expired, so a higher sample starts a probe"
        );
        assert_eq!(
            c.min_rtt.map(|(min, _)| min),
            Some(ms(55)),
            "and is not taken"
        );
    }

    #[test]
    fn an_app_limited_ack_does_not_start_a_probe() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        ack(&mut c, t0 + ms(11_000), ms(90), 0, true);
        assert!(c.probe.is_none());
        assert_eq!(c.cap(), Some(1_125_000));

        ack(&mut c, t0 + ms(12_000), ms(90), 0, false);
        assert!(c.probe.is_some());
    }

    #[test]
    fn a_probe_holds_the_window_at_half_the_bdp_and_at_least_four_packets() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        ack(&mut c, t0 + ms(10_001), ms(120), 0, false);

        assert_eq!(c.cap(), Some(450_000), "15 MB/s x 60 ms / 2");

        c.rate.samples = [10_000; SAMPLES];
        c.refresh();
        assert_eq!(c.window(), 4 * 1200, "half of 600 bytes is less");
        c.on_mtu_update(1452);
        assert_eq!(c.window(), 4 * 1452);
    }

    #[test]
    fn a_probe_ends_200_ms_or_one_srtt_after_in_flight_falls_to_its_window() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let t1 = t0 + ms(10_001);
        ack(&mut c, t1, ms(120), 0, false);

        c.on_end_acks(t1 + ms(5_000), 450_001, false, None);
        assert!(
            c.probe.as_ref().is_some_and(|p| p.ends.is_none()),
            "not drained yet"
        );
        let drained = t1 + ms(5_001);
        c.on_end_acks(drained, 450_000, false, None);
        c.on_end_acks(drained + ms(199), 0, false, None);
        assert_eq!(c.cap(), Some(450_000), "200 ms, since SRTT is 100 ms");
        c.on_end_acks(drained + ms(200), 0, false, None);
        assert!(c.probe.is_none());
        assert_eq!(c.cap(), Some(2_250_000), "1.25 x 15 MB/s x 120 ms");

        // With a smoothed RTT of 300 ms the probe lasts 300 ms.
        let mut c = estimated(t0);
        c.record_ack(t1, t1 - ms(120), 0, false, ms(300));
        c.on_end_acks(drained, 0, false, None);
        c.on_end_acks(drained + ms(299), 0, false, None);
        assert!(c.probe.is_some());
        c.on_end_acks(drained + ms(300), 0, false, None);
        assert!(c.probe.is_none());
    }

    #[test]
    fn the_new_minimum_is_the_third_lowest_arrival_of_the_probe_even_above_the_old_one() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        // The path RTT has risen from 60 to 150 ms.
        let t1 = t0 + ms(10_001);
        ack(&mut c, t1, ms(160), 0, false);
        ack(&mut c, t1 + ms(10), ms(150), 0, false);
        ack(&mut c, t1 + ms(20), ms(155), 0, false);
        end_acks(&mut c, t1 + ms(20), false);
        ack(&mut c, t1 + ms(100), ms(152), 0, false);
        assert_eq!(
            c.cap(),
            Some(450_000),
            "the probe window uses the old minimum"
        );
        end_acks(&mut c, t1 + ms(220), false);

        assert!(c.probe.is_none());
        assert_eq!(
            c.min_rtt,
            Some((ms(155), t1 + ms(220))),
            "of 160, 150, 155 and 152"
        );
        assert_eq!(c.cap(), Some(2_906_250), "1.25 x 15 MB/s x 155 ms");
    }

    #[test]
    fn a_probe_with_under_three_arrivals_takes_its_lowest_sample() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let t1 = t0 + ms(10_001);
        ack(&mut c, t1, ms(160), 0, false);
        ack(&mut c, t1 + ms(10), ms(150), 0, false);
        end_acks(&mut c, t1 + ms(10), false);
        end_acks(&mut c, t1 + ms(210), false);
        assert!(c.probe.is_none());
        assert_eq!(c.min_rtt, Some((ms(150), t1 + ms(210))));
    }

    /// quinn hands every ACK of one endpoint poll the same `now`. A poll that
    /// was held up gives samples that are too short, all under that `now`.
    #[test]
    fn the_samples_of_one_arrival_time_do_not_lower_the_minimum() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let held = t0 + ms(1_000);
        for rtt in [37, 38, 37, 39] {
            ack(&mut c, held, ms(rtt), 0, false);
        }
        assert_eq!(c.min_rtt, Some((MIN_RTT, t0)));
        assert_eq!(c.cap(), Some(1_125_000));
        // A second held-up poll within the second does not confirm it either.
        ack(&mut c, held + ms(500), ms(37), 0, false);
        assert_eq!(c.min_rtt, Some((MIN_RTT, t0)));
        // A sample at the minimum renews it and leaves the two waiting.
        ack(&mut c, held + ms(600), MIN_RTT, 0, false);
        assert_eq!(c.min_rtt, Some((MIN_RTT, held + ms(600))));
        assert_eq!(c.low.0.iter().flatten().count(), 2);
        // A third arrival exactly a second after the first confirms them.
        ack(&mut c, held + ms(1_000), ms(39), 0, false);
        assert_eq!(c.min_rtt, Some((ms(39), held + ms(1_000))));
    }

    #[test]
    fn a_lower_minimum_is_the_highest_of_three_arrivals_within_a_second() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let t1 = t0 + ms(1_000);
        ack(&mut c, t1, ms(40), 0, false);
        ack(&mut c, t1, ms(38), 0, false);
        ack(&mut c, t1 + ms(5), ms(50), 0, false);
        assert_eq!(c.min_rtt, Some((MIN_RTT, t0)));
        ack(&mut c, t1 + ms(9), ms(45), 0, false);
        assert_eq!(
            c.min_rtt,
            Some((ms(50), t1 + ms(9))),
            "of 38, 50 and 45, each the lowest of its arrival"
        );
        assert_eq!(c.cap(), Some(937_500), "1.25 x 15 MB/s x 50 ms");
        assert_eq!(c.low, LowSamples::default(), "the next one starts again");

        // An arrival more than a second old no longer counts.
        let mut c = estimated(t0);
        ack(&mut c, t1, ms(40), 0, false);
        ack(&mut c, t1 + ms(500), ms(40), 0, false);
        ack(&mut c, t1 + ms(1_001), ms(40), 0, false);
        assert_eq!(c.min_rtt, Some((MIN_RTT, t0)));
        ack(&mut c, t1 + ms(1_400), ms(40), 0, false);
        assert_eq!(c.min_rtt, Some((ms(40), t1 + ms(1_400))));
    }

    #[test]
    fn samples_taken_during_a_probe_do_not_lower_the_estimate() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let mut t = t0 + ms(10_001);
        ack(&mut c, t, ms(120), 0, false);
        assert!(c.probe.is_some());

        // In-flight data stays above the probe window, so the probe goes on,
        // and every interval delivers a tenth of the estimated rate without
        // finding the sender app-limited.
        for _ in 0..2 * SAMPLES {
            t += SRTT;
            ack(&mut c, t, MIN_RTT, 150_000, false);
            c.on_end_acks(t, 10_000_000, false, None);
        }
        assert!(
            c.probe.as_ref().is_some_and(|p| p.ends.is_none()),
            "still probing"
        );
        assert_eq!(c.rate.max(), Some(BANDWIDTH));

        // After the probe the same samples count.
        c.on_end_acks(t, 0, false, None);
        t += ms(200);
        c.on_end_acks(t, 0, false, None);
        assert!(c.probe.is_none());
        for _ in 0..SAMPLES {
            t = interval(&mut c, t, 1_500_000, false);
        }
        assert_eq!(c.rate.max(), Some(1_500_000));
    }

    #[test]
    fn a_new_connection_uses_the_startup_gain_until_three_samples_have_not_grown_by_a_quarter() {
        let mut c = starting();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 1_000_000, false);
        assert_eq!(c.cap(), Some(FLOOR), "2.885 x 60 kB is below the floor");
        for rate in [10_000_000, 20_000_000, 40_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert_eq!(c.cap(), Some(6_924_000), "2.885 x 40 MB/s x 60 ms");

        // Two samples below 1.25 x 40 MB/s, then one exactly at it.
        t = interval(&mut c, t, 49_000_000, false);
        t = interval(&mut c, t, 49_000_000, false);
        t = interval(&mut c, t, 50_000_000, false);
        assert!(!c.startup.ended, "a rise of exactly a quarter is growth");
        assert_eq!(c.cap(), Some(8_655_000), "2.885 x 50 MB/s x 60 ms");

        t = interval(&mut c, t, 62_000_000, false);
        t = interval(&mut c, t, 62_000_000, false);
        for _ in 0..SAMPLES {
            t = interval(&mut c, t, 1_000_000, true);
        }
        assert!(
            !c.startup.ended,
            "app-limited samples are not part of the test"
        );
        t = interval(&mut c, t, 62_000_000, false);
        assert!(c.startup.ended, "the third sample below 62.5 MB/s");
        assert_eq!(c.cap(), Some(4_650_000), "1.25 x 62 MB/s x 60 ms");

        interval(&mut c, t, 200_000_000, false);
        assert_eq!(
            c.cap(),
            Some(15_000_000),
            "growth does not bring the startup back"
        );
    }

    #[test]
    fn a_congestion_event_without_growth_ends_the_startup_even_when_app_limited() {
        let mut c = starting();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 10_000_000, false);

        c.on_congestion_event(t, t - MIN_RTT, false, 1200);
        t = interval(&mut c, t, 20_000_000, true);
        assert!(
            !c.startup.ended,
            "loss while the estimate grows by a quarter"
        );

        t = interval(&mut c, t, 20_000_000, false);
        assert!(
            !c.startup.ended,
            "the event belonged to the previous interval"
        );

        // An ECN mark arrives as a congestion event with no lost bytes.
        c.on_congestion_event(t, t - MIN_RTT, false, 0);
        interval(&mut c, t, 20_000_000, true);
        assert!(c.startup.ended);
        assert_eq!(c.cap(), Some(1_500_000), "1.25 x 20 MB/s x 60 ms");
    }

    /// Runs one sample interval like [`interval`] that also loses a quarter
    /// of the bytes it acknowledges, a fifth of all its bytes.
    fn lossy_interval(c: &mut Bbr, start: Instant, rate: u64) -> Instant {
        c.on_congestion_event(start, start - MIN_RTT, false, rate / 40);
        interval(c, start, rate, false)
    }

    /// Runs one sample interval like [`interval`] that loses `ppm` of all its
    /// bytes.
    fn share_interval(c: &mut Bbr, start: Instant, rate: u64, ppm: u64) -> Instant {
        let acked = rate / 10;
        let lost = acked * ppm / (1_000_000 - ppm);
        c.on_congestion_event(start, start - MIN_RTT, false, lost);
        interval(c, start, rate, false)
    }

    #[test]
    fn a_first_startup_ends_as_it_did_before_the_base_loss() {
        for before in [false, true] {
            let mut c = starting();
            if before {
                // The controller as it was before it read the base loss.
                c.base.bound = 0;
                c.base.early = u64::MAX;
                c.exit_packets = 0;
            }
            let mut t = Instant::now();
            end_acks(&mut c, t, false);
            for rate in [10_000_000, 20_000_000, 40_000_000] {
                t = lossy_interval(&mut c, t, rate);
                assert!(!c.startup.ended, "growth");
            }
            c.on_congestion_event(t, t - MIN_RTT, false, 1200);
            interval(&mut c, t, 40_000_000, false);
            assert!(
                c.startup.ended,
                "with no base loss read, any lost byte in an interval without growth ends it"
            );
        }
    }

    #[test]
    fn with_a_base_loss_the_startup_ends_above_one_and_a_half_times_it() {
        let mut c = starting();
        c.base.push(200_000);
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        for rate in [10_000_000, 20_000_000, 40_000_000] {
            t = lossy_interval(&mut c, t, rate);
        }
        t = share_interval(&mut c, t, 40_000_000, 290_000);
        assert!(!c.startup.ended, "29 percent is not above 1.5 x 20 percent");
        share_interval(&mut c, t, 40_000_000, 310_000);
        assert!(c.startup.ended, "31 percent is");
    }

    #[test]
    fn a_startup_that_lost_five_percent_starts_the_first_probe_at_the_next_ack() {
        // A startup that loses `ppm` of its bytes and ends at its first
        // interval without growth, with `reading` kept or not.
        let ended = |ppm: u64, reading: bool| {
            let mut c = starting();
            if reading {
                c.base.push(0);
            }
            let mut t = Instant::now();
            end_acks(&mut c, t, false);
            for rate in [10_000_000, 20_000_000, 40_000_000, 40_000_000] {
                t = share_interval(&mut c, t, rate, ppm);
            }
            assert!(c.startup.ended);
            (c, t)
        };

        let (mut c, t) = ended(51_000, false);
        assert!(c.probe_due);
        ack(&mut c, t + ms(1), ms(70), 0, true);
        assert!(c.probe.is_none(), "an app-limited ACK does not start it");
        ack(&mut c, t + ms(2), ms(70), 0, false);
        assert!(c.probe.is_some(), "the next ACK does, 10 s early");
        assert!(!c.probe_due);

        let (c, _) = ended(49_000, false);
        assert!(
            !c.probe_due,
            "4.9 percent waits for the minimum RTT to expire"
        );
        let (c, _) = ended(51_000, true);
        assert!(!c.probe_due, "a reading is kept");
    }

    /// A startup whose first interval acknowledges `first` bytes and grows
    /// the estimate from nothing, and whose second acknowledges `second`
    /// bytes, does not grow it by a quarter, and has a congestion event that
    /// loses `lost` bytes, an ECN mark when `lost` is zero.
    fn two_intervals(first: u64, second: u64, lost: u64, app_limited: bool) -> Bbr {
        let mut c = starting();
        let mut t = Instant::now();
        end_acks(&mut c, t, app_limited);
        if app_limited {
            // An app-limited interval runs the test only with a congestion
            // event.
            c.on_congestion_event(t, t - MIN_RTT, false, 0);
        }
        t = interval(&mut c, t, first * 10, app_limited);
        assert!(!c.startup.ended, "growth");
        c.on_congestion_event(t, t - MIN_RTT, false, lost);
        interval(&mut c, t, second * 10, app_limited);
        c
    }

    #[test]
    fn a_loss_ends_the_startup_only_once_it_has_counted_100_packets() {
        // 100 packets of 1200 bytes are 120 kB.
        let c = two_intervals(50_000, 50_000, 18_800, false);
        assert!(!c.startup.ended, "118.8 kB counted, 99 packets");
        let c = two_intervals(50_000, 50_000, 20_000, false);
        assert!(c.startup.ended, "120 kB counted, 100 packets");
    }

    #[test]
    fn an_ecn_mark_ends_the_startup_only_once_it_has_counted_100_packets() {
        let c = two_intervals(59_400, 59_400, 0, false);
        assert!(!c.startup.ended, "99 packets");
        let c = two_intervals(59_400, 60_600, 0, false);
        assert!(c.startup.ended, "100 packets");
        // A handshake: app-limited intervals of a few packets, the second
        // with a mark.
        let c = two_intervals(2_400, 2_400, 0, true);
        assert!(!c.startup.ended, "a marked handshake");
    }

    #[test]
    fn three_intervals_without_growth_end_a_startup_under_100_packets() {
        let mut c = starting();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        // 1 kB per interval.
        for _ in 0..3 {
            t = interval(&mut c, t, 10_000, false);
            assert!(!c.startup.ended);
        }
        interval(&mut c, t, 10_000, false);
        assert!(c.startup.ended, "three samples without growth, on 4 kB");
    }

    /// Closes one reading on `c`: a probe entered at `t` after a round trip
    /// of 100 ms in which 150 kB arrived, holding its window for 200 ms from
    /// 10 ms after it, with `acked` bytes arriving and `lost` lost, a ratio
    /// under 0.75. Returns when it closed.
    fn reading(c: &mut Bbr, t: Instant, acked: u64, lost: u64) -> Instant {
        c.base.enter(t, ms(100));
        c.base.on_ack(t - ms(50), 150_000);
        c.base.begin(t + ms(10));
        c.base.on_ack(t + ms(10), acked);
        c.base.on_loss(t + ms(10), lost);
        c.base.end(t + ms(210));
        let closed = t + ms(210) + SRTT * 2;
        end_acks(c, closed, false);
        closed
    }

    #[test]
    fn a_first_reading_is_confirmed_by_a_probe_ten_intervals_later() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        c.startup.ended = true;
        let mut t = reading(&mut c, t0, 150_000, 30_000);
        assert_eq!(c.base.ppm(), 166_666);
        assert_eq!(
            c.confirm,
            Some(CONFIRM_INTERVALS),
            "from zero to 16.7 percent"
        );
        for _ in 0..CONFIRM_INTERVALS - 1 {
            t = interval(&mut c, t, BANDWIDTH, false);
            assert!(!c.probe_due);
        }
        // The next ACK would start the probe, so the interval is closed by
        // hand.
        let end = t + SRTT;
        c.record_ack(end, end - MIN_RTT, BANDWIDTH / 10, false, SRTT);
        end_acks(&mut c, end, false);
        assert!(c.probe_due, "the tenth interval");
        assert_eq!(c.confirm, None, "once");

        // A further reading while the base loss is in force is not confirmed.
        let mut c = estimated(t0);
        c.startup.ended = true;
        c.base.push(200_000);
        reading(&mut c, t0, 150_000, 30_000);
        assert_eq!(c.confirm, None, "not from zero");
        // Nor is a first reading under 5 percent.
        let mut c = estimated(t0);
        c.startup.ended = true;
        reading(&mut c, t0, 150_000, 6_000);
        assert_eq!(c.base.ppm(), 38_461);
        assert_eq!(c.confirm, None, "3.8 percent");
    }

    #[test]
    fn a_short_early_probe_makes_the_next_one_due_when_it_counted_a_quarter_reading_and_lost_five_percent()
     {
        // A startup that lost 5.1 percent, then its early probe, in which the
        // packets sent while it held its window had `acked` bytes acknowledged
        // and `lost` bytes lost, and those sent in the 60 ms before it was
        // entered had `before` bytes acknowledged.
        let early = |before: u64, acked: u64, lost: u64| {
            let mut c = starting();
            let mut t = Instant::now();
            end_acks(&mut c, t, false);
            for rate in [10_000_000, 20_000_000, 40_000_000, 40_000_000] {
                t = share_interval(&mut c, t, rate, 51_000);
            }
            assert!(c.repeat && c.probe_due);
            let t1 = t + ms(2);
            ack(&mut c, t1, ms(70), 0, false);
            c.on_end_acks(t1, 0, false, None);
            assert!(
                c.probe.as_ref().is_some_and(|p| p.ends.is_some()),
                "drained"
            );
            assert!(!c.probe_due);
            ack(&mut c, t1 + ms(50), ms(100), before, false);
            ack(&mut c, t1 + ms(100), MIN_RTT, acked, false);
            c.on_congestion_event(t1 + ms(100), t1 + ms(50), false, lost);
            end_acks(&mut c, t1 + ms(200), false);
            assert!(c.probe.is_none());
            end_acks(&mut c, t1 + ms(400), false);
            c
        };

        // As much arriving before as in the probe: a ratio of 0.3.
        let c = early(28_500, 28_500, 1_500);
        assert!(
            c.probe_due && c.repeat,
            "25 packets of 1200 bytes with 5 percent lost: the next is due"
        );
        let c = early(29_000, 29_000, 1_000);
        assert!(
            !c.probe_due && !c.repeat,
            "under 5 percent lost: the repeat ends"
        );
        let c = early(28_000, 28_000, 1_999);
        assert!(
            !c.probe_due && !c.repeat,
            "under 25 packets: one early probe"
        );
        let c = early(150_000, 150_000, 0);
        assert!(c.base.has_reading());
        assert!(!c.probe_due && !c.repeat, "a kept reading stops the repeat");
        // A third as much arriving before: a ratio of 0.9.
        let c = early(9_500, 28_500, 1_500);
        assert!(matches!(
            c.last_closed,
            Some((_, Closed::Unverified { .. }))
        ));
        assert!(
            !c.probe_due && !c.repeat,
            "arrivals that did not fall end the repeat"
        );
    }

    #[test]
    fn the_steady_window_covers_the_base_loss_and_the_probe_and_the_startup_do_not() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        c.base.push(200_000);
        c.refresh();
        assert_eq!(
            c.cap(),
            Some(1_476_562),
            "1.125 MB x (1 + 0.25 x 0.2) / (1 - 0.2)"
        );
        c.base.push(500_000);
        c.refresh();
        assert_eq!(c.cap(), Some(1_476_562), "the lowest of the readings");

        let mut c = estimated(t0);
        c.base.push(400_000);
        c.refresh();
        assert_eq!(
            c.cap(),
            Some(2_062_500),
            "1.125 MB x (1 + 0.25 x 0.4) / (1 - 0.4), the bound"
        );

        ack(&mut c, t0 + ms(10_001), ms(120), 0, false);
        assert_eq!(c.cap(), Some(450_000), "the probe window is half the BDP");

        let mut c = estimated(t0);
        c.startup.ended = false;
        c.base.push(200_000);
        c.refresh();
        assert_eq!(c.cap(), Some(2_596_500), "2.885 x 15 MB/s x 60 ms");
    }

    #[test]
    fn a_probe_reads_the_base_loss_of_the_packets_sent_while_it_held_its_window() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let t1 = t0 + ms(10_001);
        ack(&mut c, t1, ms(120), 0, false);
        c.on_end_acks(t1, 0, false, None);
        assert!(
            c.probe.as_ref().is_some_and(|p| p.ends.is_some()),
            "drained"
        );

        // A packet sent before the probe held its window does not count.
        ack(&mut c, t1 + ms(50), MIN_RTT, 1_000_000, false);
        c.on_congestion_event(t1 + ms(50), t1 - ms(10), false, 1_000_000);
        ack(&mut c, t1 + ms(100), MIN_RTT, 400_000, false);
        c.on_congestion_event(t1 + ms(100), t1 + ms(10), false, 75_000);
        end_acks(&mut c, t1 + ms(100), false);
        end_acks(&mut c, t1 + ms(200), false);
        assert!(c.probe.is_none());
        // A packet sent before the probe ended, declared lost after it.
        c.on_congestion_event(t1 + ms(300), t1 + ms(150), false, 25_000);
        end_acks(&mut c, t1 + ms(399), false);
        assert_eq!(c.base.ppm(), 0, "the reading is still open");
        let cap = c.cap().expect("a cap");

        end_acks(&mut c, t1 + ms(400), false);
        assert_eq!(c.base.ppm(), 200_000, "100 kB lost of 500 kB");
        assert_eq!(c.cap(), Some(cap * 21 / 16), "(1 + 0.25 x 0.2) / (1 - 0.2)");
    }

    #[test]
    fn the_time_threshold_the_window_covers_is_quinns() {
        assert_eq!(
            LOSS_DELAY_EXTRA_PERMILLE, 250,
            "LOSS_TIME_THRESHOLD is 1.25"
        );
    }

    /// A controller whose startup ended at 15 MB/s by three samples without
    /// growth, and whose estimate has since fallen to `rate` through ten
    /// intervals at that rate. Returns it and when its last interval ended.
    fn fallen_to(rate: u64) -> (Bbr, Instant) {
        let mut c = starting();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        for _ in 0..4 {
            t = interval(&mut c, t, BANDWIDTH, false);
        }
        assert!(c.startup.ended, "three samples without growth");
        for _ in 0..SAMPLES {
            t = interval(&mut c, t, rate, false);
        }
        assert_eq!(c.rate.max(), Some(rate));
        (c, t)
    }

    #[test]
    fn the_startup_gain_returns_after_three_rises_from_below_half_the_peak() {
        let (mut c, mut t) = fallen_to(2_000_000);
        t = interval(&mut c, t, 2_200_000, false);
        // An app-limited sample in the run neither counts nor breaks it.
        t = interval(&mut c, t, 1_000_000, true);
        t = interval(&mut c, t, 2_400_000, false);
        assert!(c.startup.ended, "two rises");
        assert_eq!(
            c.cap(),
            Some(240_000),
            "1.25 x 2.4 MB/s x 60 ms is below the floor"
        );

        t = interval(&mut c, t, 4_000_000, false);
        assert!(!c.startup.ended, "the third rise");
        assert_eq!(c.cap(), Some(692_400), "2.885 x 4 MB/s x 60 ms");

        // It ends by the rules of the first startup: three samples in a row
        // without a rise of a quarter since the estimate last grew.
        t = interval(&mut c, t, 10_000_000, false);
        for _ in 0..2 {
            t = interval(&mut c, t, 12_000_000, false);
        }
        assert!(!c.startup.ended, "10 MB/s grew, 12 MB/s twice did not");
        t = interval(&mut c, t, 12_000_000, false);
        assert!(c.startup.ended);
        assert_eq!(c.cap(), Some(900_000), "1.25 x 12 MB/s x 60 ms");

        // And it can return again after the next fall.
        for _ in 0..SAMPLES {
            t = interval(&mut c, t, 1_000_000, false);
        }
        for rate in [1_100_000, 1_200_000, 1_300_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(!c.startup.ended, "15 MB/s is still the peak");
    }

    #[test]
    fn the_startup_gain_does_not_return_without_a_fall_below_half_or_three_rises_in_a_row() {
        // From 8 MB/s, above half of the 15 MB/s peak, three rises.
        let (mut c, mut t) = fallen_to(8_000_000);
        for rate in [10_000_000, 12_500_000, 16_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(c.startup.ended, "the estimate had not fallen to half");

        // From 2 MB/s, a run of rises broken by a sample that does not raise
        // the estimate.
        let (mut c, mut t) = fallen_to(2_000_000);
        for rate in [3_000_000, 4_000_000, 3_900_000, 5_000_000, 6_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(c.startup.ended, "3.9 MB/s leaves the estimate at 4 MB/s");
        interval(&mut c, t, 7_000_000, false);
        assert!(
            !c.startup.ended,
            "5, 6 and 7 MB/s are three rises from below 7.5 MB/s"
        );

        // The rise has to start below half the peak, not at it.
        let (mut c, mut t) = fallen_to(6_000_000);
        for rate in [7_000_000, 7_500_000, 8_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(c.startup.ended, "the third rise starts at 7.5 MB/s");

        // App-limited samples alone never bring it back.
        let (mut c, mut t) = fallen_to(2_000_000);
        for rate in [3_000_000, 4_000_000, 5_000_000, 7_000_000] {
            t = interval(&mut c, t, rate, true);
        }
        assert!(c.startup.ended);
    }

    #[test]
    fn a_returned_startup_keeps_the_peak_and_the_last_estimate() {
        // The peak stays at 15 MB/s: after the returned startup has ended at
        // 5 MB/s, three rises below 7.5 MB/s bring it back again.
        let (mut c, mut t) = fallen_to(2_000_000);
        for rate in [3_000_000, 4_000_000, 5_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(!c.startup.ended);
        for _ in 0..3 {
            t = interval(&mut c, t, 5_000_000, false);
        }
        assert!(c.startup.ended, "three samples without growth");
        for rate in [5_500_000, 6_000_000, 6_500_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(!c.startup.ended, "15 MB/s is still the peak");

        // The last estimate is the one the startup returned at: when only an
        // app-limited interval follows before it ends, a sample that leaves
        // the estimate at 5 MB/s is not a rise.
        let (mut c, mut t) = fallen_to(2_000_000);
        for rate in [3_000_000, 4_000_000, 5_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        c.on_congestion_event(t, t - MIN_RTT, false, 1200);
        t = interval(&mut c, t, 5_000_000, true);
        assert!(c.startup.ended);
        for rate in [5_000_000, 5_500_000, 6_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(c.startup.ended, "two rises, not three");
    }

    #[test]
    fn a_congestion_event_without_growth_ends_a_returned_startup() {
        let (mut c, mut t) = fallen_to(2_000_000);
        for rate in [3_000_000, 4_000_000, 5_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(!c.startup.ended);
        c.on_congestion_event(t, t - MIN_RTT, false, 1200);
        interval(&mut c, t, 5_500_000, true);
        assert!(c.startup.ended);
    }

    // The stored cap and window are refreshed at each change of an input. Each
    // test below changes one input and reads the stored window at once.

    #[test]
    fn the_stored_window_follows_each_new_estimate() {
        let mut c = capped();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 10_000_000, false);
        assert_eq!(c.window(), 750_000, "1.25 x 10 MB/s x 60 ms");
        interval(&mut c, t, 20_000_000, false);
        assert_eq!(c.window(), 1_500_000, "1.25 x 20 MB/s x 60 ms");
    }

    #[test]
    fn the_stored_window_follows_the_end_of_the_startup() {
        let mut c = starting();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        for _ in 0..3 {
            t = interval(&mut c, t, BANDWIDTH, false);
        }
        assert_eq!(c.window(), 2_596_500, "2.885 x 15 MB/s x 60 ms");
        interval(&mut c, t, BANDWIDTH, false);
        assert!(c.startup.ended, "the third sample without growth");
        assert_eq!(
            c.window(),
            1_125_000,
            "the same estimate at 1.25: 1.25 x 15 MB/s x 60 ms"
        );
    }

    #[test]
    fn the_stored_window_follows_a_lower_minimum_rtt() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        assert_eq!(c.window(), 1_125_000);
        for after in [10, 11, 12] {
            ack(&mut c, t0 + ms(after), ms(30), 0, false);
        }
        assert_eq!(c.window(), 562_500, "1.25 x 15 MB/s x 30 ms");
    }

    #[test]
    fn the_stored_window_follows_the_start_and_the_end_of_a_probe() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let t1 = t0 + ms(10_001);
        ack(&mut c, t1, ms(120), 0, false);
        assert_eq!(c.window(), 450_000, "the probe starts: 15 MB/s x 60 ms / 2");

        c.on_end_acks(t1, 0, false, None);
        assert_eq!(c.window(), 450_000, "in-flight data has fallen to it");
        c.on_end_acks(t1 + ms(200), 0, false, None);
        assert!(c.probe.is_none());
        assert_eq!(
            c.window(),
            2_250_000,
            "the probe ends: 1.25 x 15 MB/s x 120 ms"
        );
    }

    #[test]
    fn the_stored_window_follows_the_mtu() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        c.rate.samples = [10_000; SAMPLES];
        ack(&mut c, t0 + ms(10_001), ms(120), 0, false);
        assert_eq!(c.window(), 4 * 1200, "a probe window of four packets");
        c.on_mtu_update(1452);
        assert_eq!(c.window(), 4 * 1452);
    }

    /// The recovery rule of the module documentation, batch by batch. The
    /// recovery begins at t1 + 5 ms, and the last loss is reported to the batch
    /// at t1 + 20 ms.
    #[test]
    fn a_loss_holds_in_flight_data_for_a_round_trip_and_then_lets_it_grow() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let t1 = t0 + ms(1_000);
        // An ACK of `bytes` at t1 + `at` ms, of packets sent at t1 + `sent` ms,
        // then the end of the batch with `in_flight` bytes still in flight.
        let batch = |c: &mut Bbr, at: u64, sent: i64, bytes: u64, in_flight: u64| {
            let now = t1 + ms(at);
            let sent = if sent < 0 {
                t1 - ms(sent.unsigned_abs())
            } else {
                t1 + ms(sent.unsigned_abs())
            };
            c.record_ack(now, sent, bytes, false, SRTT);
            c.on_end_acks(now, in_flight, false, None);
        };

        c.on_congestion_event(t1, t1 - MIN_RTT, false, 100_000);
        assert_eq!(c.window(), 1_125_000, "a loss acts at the next batch");
        batch(&mut c, 5, -55, 50_000, 600_000);
        assert_eq!(c.window(), 650_000, "in-flight data plus the bytes acked");

        batch(&mut c, 10, -50, 50_000, 550_000);
        assert_eq!(
            c.window(),
            650_000,
            "acknowledged packets were sent before the recovery: no growth"
        );

        c.on_congestion_event(t1 + ms(15), t1 - ms(45), false, 30_000);
        batch(&mut c, 20, -40, 20_000, 500_000);
        assert_eq!(c.window(), 620_000, "a later loss takes its bytes off");

        batch(&mut c, 70, 10, 40_000, 500_000);
        assert_eq!(
            c.window(),
            660_000,
            "a packet sent after the recovery began: the bytes acked are added"
        );

        batch(&mut c, 80, 15, 10_000, 700_000);
        assert_eq!(
            c.window(),
            710_000,
            "the window never falls below in-flight data plus the bytes acked"
        );

        batch(&mut c, 85, 25, 10_000, 500_000);
        assert!(c.recovery.is_none(), "a packet sent after the last loss");
        assert_eq!(c.window(), 1_125_000, "back at the cap");
    }

    /// The four counts of [`Record`] that the floor is read from.
    fn floor_counts(c: &Bbr) -> (Duration, Duration, Duration, u64) {
        let r = c.record();
        (r.window_limited, r.floor, r.floor_lossless, r.peak)
    }

    /// What the close line reports of the controller. 2 MB/s at 60 ms is a
    /// bandwidth-delay product of 120 kB, so the cap is at its floor; 10 MB/s
    /// gives 750 kB.
    #[test]
    fn the_record_counts_the_time_the_window_held_the_sender_and_the_part_at_the_floor() {
        let mut c = capped();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);

        // There is no cap before the first sample, so no floor yet.
        t = interval(&mut c, t, 2_000_000, false);
        assert_eq!(
            floor_counts(&c),
            (SRTT, Duration::ZERO, Duration::ZERO, 2_000_000)
        );
        assert_eq!(c.cap(), Some(FLOOR));

        // At the floor, and nothing lost.
        t = interval(&mut c, t, 2_000_000, false);
        // At the floor, with a loss.
        c.on_congestion_event(t, t - MIN_RTT, false, 1200);
        t = interval(&mut c, t, 2_000_000, false);
        assert_eq!(floor_counts(&c), (3 * SRTT, 2 * SRTT, SRTT, 2_000_000));

        // An app-limited interval is the application's, not the window's.
        t = interval(&mut c, t, 2_000_000, true);
        assert_eq!(c.record().window_limited, 3 * SRTT);

        // The interval that raises the estimate closed with the cap still at
        // the floor; the next one closes above it.
        t = interval(&mut c, t, 10_000_000, false);
        interval(&mut c, t, 10_000_000, false);
        assert_eq!(floor_counts(&c), (5 * SRTT, 3 * SRTT, 2 * SRTT, 10_000_000));
    }

    /// The means of [`Record`], over the same intervals.
    #[test]
    fn the_record_reads_the_time_in_flight_the_base_loss_and_the_gain_as_means() {
        let mut c = capped();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        let r = c.record();
        assert_eq!(
            (
                r.flight_permille(),
                r.base_loss_mean(),
                r.base_loss_highest(),
                r.gain_mean()
            ),
            (None, None, None, None),
            "nothing counted yet"
        );

        // One interval whose bytes were all in flight for one minimum RTT, at
        // the top gain and without a base loss. The window of 240 kB was held
        // for 100 ms, which is 400 kB of window per minimum RTT of 60 ms, and
        // 200 kB were delivered: two minimum RTTs per window.
        t = interval(&mut c, t, 2_000_000, false);
        let r = c.record();
        assert_eq!(
            (
                r.flight_permille(),
                r.base_loss_mean(),
                r.base_loss_highest(),
                r.gain_mean()
            ),
            (Some(1000), Some(0), Some(0), Some(1250))
        );
        assert_eq!(r.turnover_permille(), Some(2000));

        // A second one of the same length: a third of its bytes were in flight
        // for one minimum RTT and two thirds for two, a base loss of 0.10 is in
        // force and the gain is 1.05. Of the bytes of both intervals, half were
        // in flight for two minimum RTTs.
        assert!(c.base.push(100_000));
        c.gain.permille = 1_050;
        let end = t + SRTT;
        ack(&mut c, end, MIN_RTT, 100_000, false);
        ack(&mut c, end, 2 * MIN_RTT, 300_000, false);
        end_acks(&mut c, end, false);
        let r = c.record();
        assert_eq!(r.window_limited, 2 * SRTT);
        assert_eq!(
            (
                r.flight_permille(),
                r.base_loss_mean(),
                r.base_loss_highest(),
                r.gain_mean()
            ),
            (Some(1500), Some(50_000), Some(100_000), Some(1150))
        );
        assert_eq!(
            r.turnover_permille(),
            Some(1333),
            "the same window for twice the time, and 600 kB delivered"
        );

        // An app-limited interval adds nothing, and its bytes do not wait for
        // the next one.
        let end = end + SRTT;
        ack(&mut c, end, 3 * MIN_RTT, 400_000, true);
        end_acks(&mut c, end, true);
        let end = end + SRTT;
        ack(&mut c, end, MIN_RTT, 200_000, false);
        end_acks(&mut c, end, false);
        assert_eq!(c.record().window_limited, 3 * SRTT);
        assert_eq!(
            c.record().flight_permille(),
            Some(1375),
            "800 kB, 300 of them for two minimum RTTs"
        );
    }

    #[test]
    fn the_record_leaves_out_a_startup_and_a_probe() {
        // A startup: its window is not the steady one.
        let mut c = starting();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 2_000_000, false);
        assert!(!c.startup.ended);
        assert_eq!(c.record(), Record::default());

        // A probe: it holds the window low on purpose, and its ACKs count
        // as app-limited.
        let mut c = capped();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 2_000_000, false);
        let before = c.record();
        c.probe = Some(Probe {
            min: MIN_RTT,
            ends: None,
        });
        interval(&mut c, t, 2_000_000, false);
        assert_eq!(c.record(), before);
    }

    #[test]
    fn a_recovery_never_holds_the_window_below_four_packets() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        c.on_congestion_event(t0, t0 - MIN_RTT, false, 100_000);
        c.on_end_acks(t0 + ms(5), 0, false, None);
        assert_eq!(c.window(), 4 * 1200);
    }

    #[test]
    fn an_ecn_mark_starts_no_recovery() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        c.on_congestion_event(t0, t0 - MIN_RTT, false, 0);
        c.on_end_acks(t0 + ms(5), 100_000, false, None);
        assert!(c.recovery.is_none());
        assert_eq!(c.window(), 1_125_000);
    }

    /// A recovery that begins during the startup does not lower the window
    /// until the startup has ended, and then it does at once.
    #[test]
    fn a_recovery_limits_the_window_only_after_the_startup() {
        let t0 = Instant::now();
        let mut c = starting();
        c.rate.samples = [BANDWIDTH; SAMPLES];
        ack(&mut c, t0, MIN_RTT, 0, false);
        c.on_congestion_event(t0, t0 - MIN_RTT, false, 1200);
        let mut t = t0 + ms(5);
        ack(&mut c, t, MIN_RTT, 10_000, false);
        c.on_end_acks(t, 100_000, false, None);
        assert_eq!(c.recovery.map(|r| r.window), Some(110_000));
        assert_eq!(
            c.window(),
            250_000,
            "the slow-start limit, 240 kB plus 10 kB acknowledged, not the recovery window"
        );

        // The first interval grows the estimate from nothing; the second has a
        // congestion event and no growth, and with it the startup has counted
        // 133.6 kB, over 100 packets, so it ends the startup.
        for _ in 0..2 {
            c.on_congestion_event(t, t - MIN_RTT, false, 1200);
            t += SRTT;
            ack(&mut c, t, MIN_RTT, 60_000, false);
            c.on_end_acks(t, 100_000, false, None);
        }
        assert!(c.startup.ended);
        assert_eq!(
            c.window(),
            227_600,
            "110 kB, then twice 1200 bytes lost and 60 kB acked"
        );
    }

    /// What a [`Shadowed`] controller saw on a real connection.
    #[derive(Debug, Default)]
    struct Shadow {
        acks: u64,
        /// Every point where the stored cap or window differed from a fresh
        /// computation, or the controller did not hold quinn's smoothed RTT.
        mismatches: Vec<String>,
        min_rtt: Option<Duration>,
        estimate: Option<u64>,
    }

    /// A [`Bbr`] that quinn drives, which is the one way to call
    /// [`Controller::on_ack`] with a real [`RttEstimator`], checked after every
    /// callback.
    #[derive(Debug, Clone)]
    struct Shadowed {
        capped: Bbr,
        shadow: Arc<Mutex<Shadow>>,
    }

    impl Shadowed {
        fn compare(&self, after: &str, srtt: Option<Duration>) {
            let mut shadow = self.shadow.lock().expect("the shadow lock");
            let mut fresh = self.capped.clone();
            fresh.refresh();
            let stored = (self.capped.cap, self.capped.window);
            // During the first startup the slow-start limit moves with each
            // ACK and the window is stored once per ACK batch, which is when
            // quinn reads it next.
            let between_batches = after == "on_ack" && self.capped.slow_start.is_some();
            if (fresh.cap, fresh.window) != stored && !between_batches {
                let computed = (fresh.cap, fresh.window);
                shadow.mismatches.push(format!(
                    "after {after}: stored {stored:?}, computed {computed:?}"
                ));
            }
            if let Some(srtt) = srtt
                && self.capped.srtt != srtt
            {
                let held = self.capped.srtt;
                shadow
                    .mismatches
                    .push(format!("after {after}: srtt {held:?}, quinn {srtt:?}"));
            }
            shadow.min_rtt = self.capped.min_rtt.map(|(min, _)| min);
            shadow.estimate = self.capped.rate.max();
        }
    }

    impl Controller for Shadowed {
        fn on_ack(
            &mut self,
            now: Instant,
            sent: Instant,
            bytes: u64,
            app_limited: bool,
            rtt: &RttEstimator,
        ) {
            self.capped.on_ack(now, sent, bytes, app_limited, rtt);
            self.shadow.lock().expect("the shadow lock").acks += 1;
            self.compare("on_ack", Some(rtt.get()));
        }

        fn on_end_acks(
            &mut self,
            now: Instant,
            in_flight: u64,
            app_limited: bool,
            largest_packet_num_acked: Option<u64>,
        ) {
            self.capped
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
            self.compare("on_end_acks", None);
        }

        fn on_congestion_event(
            &mut self,
            now: Instant,
            sent: Instant,
            is_persistent_congestion: bool,
            lost_bytes: u64,
        ) {
            self.capped
                .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
            self.compare("on_congestion_event", None);
        }

        fn on_mtu_update(&mut self, new_mtu: u16) {
            self.capped.on_mtu_update(new_mtu);
            self.compare("on_mtu_update", None);
        }

        fn window(&self) -> u64 {
            self.capped.window()
        }

        fn clone_box(&self) -> Box<dyn Controller> {
            Box::new(self.clone())
        }

        fn initial_window(&self) -> u64 {
            self.capped.initial_window()
        }

        fn into_any(self: Box<Self>) -> Box<dyn Any> {
            self
        }
    }

    #[derive(Debug)]
    struct ShadowedConfig(Arc<Mutex<Shadow>>);

    impl ControllerFactory for ShadowedConfig {
        fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
            Box::new(Shadowed {
                capped: build(current_mtu),
                shadow: self.0.clone(),
            })
        }
    }

    /// `on_ack` hands `record_ack` quinn's smoothed RTT, and the stored cap and
    /// window match a fresh computation after every callback: the server sends
    /// 8 MB over a real connection.
    #[tokio::test]
    async fn on_ack_records_quinns_smoothed_rtt_and_the_stored_window_stays_current() {
        const BYTES: usize = 8_000_000;
        let shadow = Arc::new(Mutex::new(Shadow::default()));
        let mut transport = quinn::TransportConfig::default();
        transport.congestion_controller_factory(Arc::new(ShadowedConfig(shadow.clone())));
        let (client, server) = crate::quic::tests::loopback_pair(transport).await;

        let write = async {
            let mut stream = server.open_uni().await.expect("open a stream");
            stream.write_all(&vec![0; BYTES]).await.expect("write");
            stream.finish().expect("finish");
            stream.stopped().await.expect("the peer reads to the end");
        };
        let read = async {
            let mut stream = client.accept_uni().await.expect("accept the stream");
            stream.read_to_end(BYTES).await.expect("read").len()
        };
        let ((), received) = tokio::join!(write, read);
        assert_eq!(received, BYTES);

        let shadow = shadow.lock().expect("the shadow lock");
        assert!(
            shadow.acks > 100,
            "only {} ACKs reached the controller",
            shadow.acks
        );
        assert_eq!(shadow.mismatches, Vec::<String>::new());
        assert!(
            shadow.min_rtt.is_some_and(|min| !min.is_zero()),
            "the RTT sample is now - sent: {:?}",
            shadow.min_rtt
        );
        assert!(shadow.estimate.is_some(), "on_ack fed the delivery rate");
    }
}
